use super::chal39::{RsaKeyPair, RsaPubKey};
use super::mod_inv;
use num::{bigint::RandBigInt, pow::Pow, BigUint, FromPrimitive, One, Zero};
use std::cmp;

#[allow(clippy::many_single_char_names, non_snake_case)]
/// Implementation of BB'98 CCA padding oracle attack, returns the decrypted message
pub fn rsa_padding_oracle_attack(pk: &RsaPubKey, ct: &BigUint, oracle: &Oracle) -> BigUint {
    println!("Bleichenbacher padding oracle attack ... (take many many minutes)");
    let n = pk.n.clone();
    let mut rng = rand::thread_rng();
    let mut M: Vec<Range> = vec![];
    let mut s_last = BigUint::zero();
    let mut s_new = BigUint::zero();
    // B = 2 ^ (n - 16)
    let B = BigUint::from_u32(2).unwrap().pow(&n.bits() - 16);
    let B_double = &B * BigUint::from_u32(2).unwrap();
    let B_triple = &B * BigUint::from_u32(2).unwrap();
    let B_triple_minus_one = &B_triple - BigUint::one();

    // Step 1: Blinding
    println!("Starting step 1: blinding ...");
    let mut s_0 = BigUint::zero();
    while s_0 == BigUint::zero() || !oracle.oracle_query(&(ct * pk.encrypt(&s_0))) {
        s_0 = rng.gen_biguint_below(&pk.n);
    }
    M.push(Range::new(&B_double, &B_triple_minus_one));

    let mut i = 1;
    // =================
    loop {
        // Step 2: Adaptive chosen s value search
        if i == 1 {
            // step 2.a starting the search
            for s in Range::new(&(&n / &B_triple), &n) {
                // the smallest s >= n/3B that's PKCS conforming
                if oracle.oracle_query(&(ct * pk.encrypt(&s))) {
                    s_new = s;
                }
            }
        } else {
            if M.len() > 1 {
                // step 2.b
                for s in Range::new(&s_last, &n) {
                    if oracle.oracle_query(&(ct * pk.encrypt(&s))) {
                        s_new = s;
                    }
                }
            } else {
                // step 2.c
                assert_eq!(M.len(), 1);
                let a = &M[0].start;
                let b = &M[0].stop;
                // ri >= 2 * (b * s_i-1 - B) / n
                let mut r_min = &BigUint::from_u32(2).unwrap() * (b * &s_last - &B) / &n;
                'outer: loop {
                    let s_min = (&B_double + &r_min * &n) / b;
                    let s_max = (&B_triple + &r_min * &n) / a;
                    for s in Range::new(&s_min, &s_max) {
                        if oracle.oracle_query(&(ct * pk.encrypt(&s))) {
                            s_new = s;
                            break 'outer;
                        }
                    }
                    r_min += BigUint::one();
                }
            }
        }
        println!("New s_i: {}", &s_new);
        // =================

        // Step 3: Narrowing the solution range
        M = M
            .into_iter()
            .flat_map(|interval| {
                let a = &interval.start;
                let b = &interval.stop;
                let r_min = ceil(&(a * &s_new - &B_triple_minus_one), &n);
                let r_max = (b * &s_new - &B_double) / &n;

                let mut range_candidates = vec![];
                for r in Range::new(&r_min, &r_max) {
                    let range_candidate = Range {
                        start: (&B_double + &r * &n) / &s_new,
                        stop: (&B_triple_minus_one + &r * &n) / &s_new,
                    };
                    if let Some(intersect) = range_candidate.intersect(&interval) {
                        range_candidates.push(intersect);
                    }
                }
                if range_candidates.len() == 0 {
                    vec![interval]
                } else {
                    range_candidates
                }
            })
            .collect();
        println!("M: {:?}", M);
        // =================

        // Step 4: Terminate or Repeat (back to step 2)
        if M.len() == 1 && M[0].start == M[0].stop {
            return (&M[0].start * mod_inv(&s_0, &n).unwrap()) % n;
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
}

impl Oracle {
    pub fn new(key_pair: &RsaKeyPair) -> Oracle {
        Oracle {
            key_pair: key_pair.clone(),
        }
    }

    pub fn oracle_query(&self, ct: &BigUint) -> bool {
        self.key_pair.priKey.bb_oracle(&ct)
    }
}

#[derive(Debug)]
// inclusive range [start, stop]
struct Range {
    pub start: BigUint,
    pub stop: BigUint,
}

impl Range {
    pub fn new(start: &BigUint, stop: &BigUint) -> Self {
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
fn ceil(num: &BigUint, dem: &BigUint) -> BigUint {
    let rem = num % dem;
    if rem > BigUint::zero() {
        num / dem + BigUint::one()
    } else {
        num / dem
    }
}
