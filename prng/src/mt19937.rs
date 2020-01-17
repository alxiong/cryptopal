#![allow(non_snake_case)]
pub use rand_core::{impls, Error, RngCore};
use std::cmp::Ordering;
use std::fmt;

#[rustfmt::skip]
pub struct Coefficients<T> {
    pub w: u8, pub n: u32, pub m: u32, pub r: u8,
    pub a: T,
    pub b: T, pub c: T,
    pub s: T, pub t: T,
    pub u: T, pub d: T, pub l: T,
    pub f: T,
}

impl<T> fmt::Debug for Coefficients<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}bit Coefficient", self.w)
    }
}

// NOTE: `if` and `match` in const is still a nightly feature
// see: https://blog.rust-lang.org/inside-rust/2019/11/25/const-if-match.html
#[rustfmt::skip]
pub const COEFF_32: Coefficients<u32> = Coefficients {
    w: 32, n: 624, m: 397, r: 31,
    a: 0x9908B0DF,
    u: 11, d: 0xFFFFFFFF,
    s: 7,  b: 0x9D2C5680,
    t: 15, c: 0xEFC60000,
    l: 18,
    f: 1812433253,
};

#[derive(Debug)]
pub struct MT19937Rng {
    mt: Vec<u32>,
    index: usize,
}

impl MT19937Rng {
    /// Instantiate a new RNG and init with the provided seed
    pub fn new(seed: u32) -> MT19937Rng {
        let mut rng = MT19937Rng {
            mt: vec![0 as u32; COEFF_32.n as usize],
            index: COEFF_32.m as usize + 1,
        };
        rng.init(seed);
        rng
    }

    pub fn from(mt: &[u32], index: usize) -> MT19937Rng {
        MT19937Rng {
            mt: mt.to_owned(),
            index,
        }
    }

    // Initialize the generator from a seed
    fn init(&mut self, seed: u32) {
        self.mt[0] = seed;
        for i in 1..COEFF_32.n as usize {
            self.mt[i] = COEFF_32
                .f
                .wrapping_mul(self.mt[i - 1] ^ (self.mt[i - 1] >> (COEFF_32.w - 2)))
                .wrapping_add(i as u32);
        }
        self.index = COEFF_32.n as usize;
    }

    // Extract a tempered value based on MT[index]
    // calling twist() every n numbers
    fn extract(&mut self) -> u32 {
        match self.index.cmp(&(COEFF_32.n as usize)) {
            Ordering::Equal => self.twist(),
            Ordering::Greater => panic!("Generator never seeded"), // should never reach here
            _ => {}
        };

        let mut y = self.mt[self.index];
        y ^= (y >> COEFF_32.u) & COEFF_32.d;
        y ^= (y << COEFF_32.s) & COEFF_32.b;
        y ^= (y << COEFF_32.t) & COEFF_32.c;
        y ^= y >> COEFF_32.l;

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        let lower_mask: u32 = (1 << COEFF_32.r) - 1;
        let upper_mask: u32 = !lower_mask;

        for i in 0..COEFF_32.n as usize {
            let x =
                (self.mt[i] & upper_mask) + (self.mt[(i + 1) % COEFF_32.n as usize] & lower_mask);
            let mut xA = x >> 1;
            if x % 2 != 0 {
                xA ^= COEFF_32.a;
            }
            self.mt[i] = self.mt[(i + COEFF_32.m as usize) % COEFF_32.n as usize] ^ xA;
        }
        self.index = 0;
    }
}

impl RngCore for MT19937Rng {
    fn next_u32(&mut self) -> u32 {
        self.extract()
    }

    fn next_u64(&mut self) -> u64 {
        ((self.extract() as u64) << 32) + self.extract() as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mt19937_correctness() {
        // since my laptop is a 64-bit machine, usize should have 8 bytes
        let mut rng = MT19937Rng::new(5489u32);
        // result refernce against: http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/VERSIONS/C-LANG/mt19937-64.c
        let expected_first_ten: [u32; 10] = [
            3499211612, 581869302, 3890346734, 3586334585, 545404204, 4161255391, 3922919429,
            949333985, 2715962298, 1323567403,
        ];
        let expected_last_ten: [u32; 10] = [
            1787387521, 1861566286, 3616058184, 48071792, 3577350513, 297480282, 1101405687,
            1473439254, 2634793792, 1341017984,
        ];
        let mut result: Vec<u32> = vec![];
        for _ in 0..1000 {
            result.push(rng.next_u32());
        }
        assert_eq!(result[..10], expected_first_ten);
        assert_eq!(result[990..], expected_last_ten);
    }
}
