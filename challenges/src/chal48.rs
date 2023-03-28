use super::chal39::{RsaKeyPair, RsaPubKey};
use super::mod_inv;
use num::{traits::Pow, BigUint, FromPrimitive, One, Zero};
use std::cmp;
use std::fmt;
use std::thread;
use std::time::Duration;

#[allow(clippy::many_single_char_names, non_snake_case)]
/// Implementation of BB'98 CCA padding oracle attack, returns the decrypted message
pub fn rsa_padding_oracle_attack(pk: &RsaPubKey, ct: &BigUint, oracle: &mut Oracle) -> BigUint {
    // For UX only
    let mut minutes = 1;
    let _ = thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(60));
        println!("⌛ {} minutes has passed!", minutes);
        minutes += 1;
    });

    println!("Bleichenbacher padding oracle attack ... (take many many minutes)");
    let n = &pk.n.clone();
    let mut M: Vec<Range> = vec![];
    let mut s_last = BigUint::zero();
    let mut s_new = BigUint::zero();
    // B = 2 ^ (n - 16)
    let two = &BigUint::from_u32(2).unwrap();
    let three = &BigUint::from_u32(3).unwrap();
    let B = &(Pow::pow(two, n.bits() - 16));
    let B_double = &(B * two);
    let B_triple = &(B * three);
    let B_triple_minus_one = &(B_triple - BigUint::one());

    // Step 1: Blinding
    println!("\nStarting step 1: blinding ...");
    let s_0 = BigUint::one();
    M.push(Range::new(&B_double, &B_triple_minus_one));

    let mut i = 1;
    // =================
    println!("\nStarting step 2~4: searching and narrowing ...");
    loop {
        // Step 2: Adaptive chosen s value search
        if i == 1 {
            // step 2.a starting the search
            println!("\nExecuting 2.a");
            s_new = div_ceil(&n, &B_triple);
            while !oracle.oracle_query(&(ct * pk.encrypt(&s_new))) {
                s_new += BigUint::one();
            }
        } else if M.len() > 1 {
            // step 2.b
            println!("\nExecuting 2.b");
            while s_new == s_last || !oracle.oracle_query(&(ct * pk.encrypt(&s_new))) {
                s_new += BigUint::one();
            }
        } else {
            // step 2.c
            println!("\nExecuting 2.c");
            assert_eq!(M.len(), 1);
            let a = &M[0].start;
            let b = &M[0].stop;

            // r_i >= 2 * (b * s_i-1 - B) / n
            let r_min = two * div_ceil(&(b * &s_last - B), &n);
            'outer: for r in Range::new(&r_min, n) {
                let s_min = (B_double + &r * n) / b;
                let s_max = (B_triple + &r * n) / a;
                assert!(s_min <= s_max);

                for s in Range::new(&s_min, &s_max) {
                    if oracle.oracle_query(&(ct * pk.encrypt(&s))) {
                        s_new = s;
                        break 'outer;
                    }
                }
            }
        }

        assert!(oracle.oracle_query(&(ct * pk.encrypt(&s_new))));
        println!("New s_i: {}", &s_new);
        // =================

        // Step 3: Narrowing the solution range
        println!("\nExecuting narrowing");
        let mut M_new: Vec<Range> = vec![];
        M.into_iter().for_each(|interval| {
            let a = &interval.start;
            let b = &interval.stop;
            let r_min = (a * &s_new - B_triple_minus_one) / n;
            let r_max = (b * &s_new - B_double) / n;

            for r in Range::new(&r_min, &r_max) {
                let range_candidate = Range::new(
                    &div_ceil(&(B_double + &r * n), &s_new),
                    &((B_triple_minus_one + &r * n) / &s_new),
                );

                if let Some(intersect) = range_candidate.intersect(&interval) {
                    M_new.push(intersect);
                }
            }

            if M_new.is_empty() {
                M_new.push(interval);
            }
        });
        M = M_new;
        println!("M: {:#?}", M);
        // =================

        // Step 4: Terminate or Repeat (back to step 2)
        if M.len() == 1 && M[0].start == M[0].stop {
            println!("\nTotal queries: {}", oracle.query_times.to_str_radix(10));
            return (&M[0].start * mod_inv(&s_0, n).unwrap()) % n;
        } else {
            s_last = s_new.clone();
            i += 1;
        }
        // =================
    }
}

/// Bleichenbacher oracle
pub struct Oracle {
    key_pair: RsaKeyPair,
    pub query_times: BigUint,
}

impl Oracle {
    pub fn new(key_pair: &RsaKeyPair) -> Oracle {
        Oracle {
            key_pair: key_pair.clone(),
            query_times: BigUint::zero(),
        }
    }

    pub fn oracle_query(&mut self, ct: &BigUint) -> bool {
        self.query_times += BigUint::one();
        // could use the following to keep track of query times
        // if &self.query_times % &BigUint::parse_bytes(b"1024", 10).unwrap() == BigUint::zero() {
        //     println!("Another 2^10 queries");
        // }
        self.key_pair.priKey.bb_oracle(&(ct % &self.key_pair.pubKey.n))
    }
}

#[derive(Clone, PartialEq)]
// inclusive range [start, stop]
struct Range {
    pub start: BigUint,
    pub stop: BigUint,
}

impl Range {
    pub fn new(start: &BigUint, stop: &BigUint) -> Self {
        assert!(start <= stop);
        Range {
            start: start.clone(),
            stop: stop.clone(),
        }
    }

    pub fn intersect(&self, range: &Range) -> Option<Range> {
        if self.stop < range.start || self.start > range.stop {
            None
        } else {
            Some(Range {
                start: cmp::max(self.start.clone(), range.start.clone()),
                stop: cmp::min(self.stop.clone(), range.stop.clone()),
            })
        }
    }
}

impl fmt::Debug for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entry(&self.start.to_str_radix(16))
            .entry(&self.stop.to_str_radix(16))
            .finish()
    }
}

impl Iterator for Range {
    type Item = BigUint;
    fn next(&mut self) -> Option<Self::Item> {
        if self.start <= self.stop {
            let result = self.start.clone();
            self.start += BigUint::one();
            Some(result)
        } else {
            None
        }
    }
}

// returns ceiling(num/dem)
fn div_ceil(num: &BigUint, dem: &BigUint) -> BigUint {
    let rem = num % dem;
    if rem > BigUint::zero() {
        num / dem + BigUint::one()
    } else {
        num / dem
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn range_intersect() {
        let r1 = Range::new(&BigUint::one(), &BigUint::parse_bytes(b"10", 10).unwrap());
        let r2 = Range::new(
            &BigUint::parse_bytes(b"3", 10).unwrap(),
            &BigUint::parse_bytes(b"7", 10).unwrap(),
        );
        assert_eq!(r1.intersect(&r2), Some(r2.clone()));
        let r3 = Range::new(
            &BigUint::parse_bytes(b"8", 10).unwrap(),
            &BigUint::parse_bytes(b"15", 10).unwrap(),
        );
        assert_eq!(
            r1.intersect(&r3),
            Some(Range::new(
                &BigUint::parse_bytes(b"8", 10).unwrap(),
                &BigUint::parse_bytes(b"10", 10).unwrap(),
            ))
        );
        let r4 = Range::new(
            &BigUint::parse_bytes(b"12", 10).unwrap(),
            &BigUint::parse_bytes(b"20", 10).unwrap(),
        );
        assert_eq!(r1.intersect(&r4), None);
        let r5 = Range::new(
            &BigUint::parse_bytes(b"10", 10).unwrap(),
            &BigUint::parse_bytes(b"10", 10).unwrap(),
        );
        assert_eq!(
            r1.intersect(&r5),
            Some(Range::new(
                &BigUint::parse_bytes(b"10", 10).unwrap(),
                &BigUint::parse_bytes(b"10", 10).unwrap(),
            ))
        );
    }
}
