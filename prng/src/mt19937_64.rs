#![allow(non_snake_case)]
pub use rand_core::{impls, Error, RngCore};
use std::cmp::Ordering;
use std::fmt;
use std::mem;

#[rustfmt::skip]
struct Coefficients {
    w: u8, n: usize, m: usize, r: u8,
    a: usize,
    b: usize, c: usize,
    s: usize, t: usize,
    u: usize, d: usize, l: usize,
    f: usize,
}

impl fmt::Debug for Coefficients {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}bit Coefficient", self.w)
    }
}

// NOTE: `if` and `match` in const is still a nightly feature
// see: https://blog.rust-lang.org/inside-rust/2019/11/25/const-if-match.html
#[rustfmt::skip]
const COEFF_32: Coefficients = Coefficients {
    w: 32, n: 624, m: 397, r: 31,
    a: 0x9908B0DF,
    u: 11, d: 0xFFFFFFFF,
    s: 7, b: 0x9D2C5680,
    t: 15, c: 0xEFC60000,
    l: 18,
    f: 1812433253,
};

#[rustfmt::skip]
const COEFF_64: Coefficients = Coefficients {
    w: 64, n: 312, m: 156, r: 31,
    a: 0xB5026F5AA96619E9,
    u: 29, d: 0x5555555555555555,
    s: 17, b: 0x71D67FFFEDA60000,
    t: 37, c: 0xFFF7EEE000000000,
    l: 43,
    f: 6364136223846793005,
};

#[derive(Debug)]
pub struct MT19937Rng {
    coeff: Coefficients,
    mt: Vec<usize>,
    index: usize,
}

impl MT19937Rng {
    /// Instantiate a new RNG and init with the provided seed
    pub fn new(seed: usize) -> MT19937Rng {
        let coeff = match mem::size_of::<usize>() {
            4 => COEFF_32,
            8 => COEFF_64,
            _ => panic!("Only 32-bit and 64-bit word size supported!"),
        };
        let mut rng = MT19937Rng {
            mt: vec![0 as usize; coeff.n],
            index: coeff.m + 1, // as a signal of uninitiated yet
            coeff,
        };
        rng.init(seed);
        rng
    }

    // Initialize the generator from a seed
    fn init(&mut self, seed: usize) {
        self.mt[0] = seed;
        for i in 1..self.coeff.n {
            self.mt[i] = self
                .coeff
                .f
                .wrapping_mul(self.mt[i - 1] ^ (self.mt[i - 1] >> (self.coeff.w - 2)))
                .wrapping_add(i);
        }
        self.index = self.coeff.n;
    }

    // Extract a tempered value based on MT[index]
    // calling twist() every n numbers
    fn extract(&mut self) -> usize {
        match self.index.cmp(&self.coeff.n) {
            Ordering::Equal => self.twist(),
            Ordering::Greater => panic!("Generator never seeded"), // should never reach here
            _ => {}
        };

        let mut y = self.mt[self.index];
        y ^= (y >> self.coeff.u) & self.coeff.d;
        y ^= (y << self.coeff.s) & self.coeff.b;
        y ^= (y << self.coeff.t) & self.coeff.c;
        y ^= y >> self.coeff.l;

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        let lower_mask: usize = (1 << self.coeff.r) - 1;
        let upper_mask: usize = !lower_mask;

        for i in 0..self.coeff.n {
            let x = (self.mt[i] & upper_mask) + (self.mt[(i + 1) % self.coeff.n] & lower_mask);
            let mut xA = x >> 1;
            if x % 2 != 0 {
                xA ^= self.coeff.a;
            }
            self.mt[i] = self.mt[(i + self.coeff.m) % self.coeff.n] ^ xA;
        }
        self.index = 0;
    }
}

impl RngCore for MT19937Rng {
    fn next_u32(&mut self) -> u32 {
        self.extract() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let next = self.extract();
        match mem::size_of::<usize>() {
            8 => next as u64,
            4 => ((next << 32) + self.extract()) as u64,
            _ => panic!("Only support 32-bit and 64-bit now"),
        }
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
    fn mt19937_64_correctness() {
        // since my laptop is a 64-bit machine, usize should have 8 bytes
        let mut rng = MT19937Rng::new(0 as usize);
        // result refernce against: http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/VERSIONS/C-LANG/mt19937-64.c
        let expected_first_ten: [u64; 10] = [
            2947667278772165694,
            18301848765998365067,
            729919693006235833,
            11021831128136023278,
            10003392056472839596,
            1054412044467431918,
            11649642299870863663,
            7813497161378842344,
            15536964167022953318,
            16718309832681015833,
        ];
        let expected_last_ten: [u64; 10] = [
            6945595858053388608,
            4207204007772020392,
            14564262508755990780,
            16401432929737352510,
            1881820450581633227,
            15293367414509766373,
            8471495498483429701,
            11665683480083006762,
            16715320457080910775,
            13588344625309223635,
        ];
        let mut result: Vec<u64> = vec![];
        for _ in 0..1000 {
            result.push(rng.next_u64());
        }
        assert_eq!(result[..10], expected_first_ten);
        assert_eq!(result[990..], expected_last_ten);
    }
}
