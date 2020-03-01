use prng::mt19937::{MT19937Rng, RngCore, COEFF_32};

fn temper(x: u32) -> u32 {
    let mut y = x;
    y ^= (y >> COEFF_32.u) & COEFF_32.d;
    y ^= (y << COEFF_32.s) & COEFF_32.b;
    y ^= (y << COEFF_32.t) & COEFF_32.c;
    y ^= y >> COEFF_32.l;
    y
}

// for simplicity, we directly use numbers instead of general algorithm to reverse
// XORAsign with Shift
fn untemper(y: u32) -> u32 {
    // reverse: y ^= y >> COEFF_32.l;
    // l=18
    let first_18 = y >> (32 - 18);
    let last_14 = (y & 0x3fff) ^ (first_18 >> 4);
    let mut x = (first_18 << 14).checked_add(last_14).unwrap();

    // reverse: y ^= (y << COEFF_32.t) & COEFF_32.c;
    // t=15, c=0xEFC60000
    let last_15 = x & 0x7fff;
    let second_last_15 = (x >> 15 & 0x7fff) ^ (COEFF_32.c >> 15 & 0x7fff & last_15);
    let first_2 = (x >> 30) ^ (COEFF_32.c >> 30 & second_last_15 & 0x3);
    x = (first_2 << 30)
        .checked_add(second_last_15 << 15)
        .unwrap()
        .checked_add(last_15)
        .unwrap();

    // reverse: y ^= (y << COEFF_32.s) & COEFF_32.b;
    // s=7, b=0x9D2C5680
    let last_7 = x & 0x7f;
    let second_last_7 = (x >> 7 & 0x7f) ^ (COEFF_32.b >> 7 & 0x7f & last_7);
    let third_last_7 = (x >> 14 & 0x7f) ^ (COEFF_32.b >> 14 & 0x7f & second_last_7);
    let forth_last_7 = (x >> 21 & 0x7f) ^ (COEFF_32.b >> 21 & 0x7f & third_last_7);
    let first_4 = (x >> 28) ^ (COEFF_32.b >> 28 & forth_last_7 & 0xf);
    x = (first_4 << 28)
        .checked_add(forth_last_7 << 21)
        .unwrap()
        .checked_add(third_last_7 << 14)
        .unwrap()
        .checked_add(second_last_7 << 7)
        .unwrap()
        .checked_add(last_7)
        .unwrap();

    // reverse: y ^= (y >> COEFF_32.u) & COEFF_32.d;
    // u=11;
    let first_11 = x >> 21;
    let second_11 = (x >> 10 & 0x7ff) ^ (COEFF_32.d >> 10 & 0x7ff & first_11);
    let last_10 = (x & 0x3ff) ^ (COEFF_32.d & 0x3ff & second_11 >> 1);
    x = (first_11 << 21)
        .checked_add(second_11 << 10)
        .unwrap()
        .checked_add(last_10)
        .unwrap();
    x
}

fn clone_mt19937(mt19937: &mut MT19937Rng) -> MT19937Rng {
    let mut mt: Vec<u32> = vec![];
    for _ in 0..COEFF_32.n {
        mt.push(untemper(mt19937.next_u32()));
    }
    let mut clone = MT19937Rng::from(&mt, 0);
    for _ in 0..COEFF_32.n {
        clone.next_u32(); // since the original also mutated a cycle 624 times
    }
    clone
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untemper_correctness() {
        for _ in 0..100 {
            let r = rand::random::<u32>();
            assert_eq!(untemper(temper(r)), r);
        }
    }

    #[test]
    fn can_predict_by_clone() {
        let mut origin = MT19937Rng::new(rand::random::<u32>());
        let mut clone = clone_mt19937(&mut origin);
        for _ in 0..1000 {
            assert_eq!(origin.next_u32(), clone.next_u32());
        }
    }
}
