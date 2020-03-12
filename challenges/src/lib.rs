#![deny(clippy::all)]
#![allow(dead_code, non_snake_case)]
#![feature(proc_macro_hygiene, decl_macro)]

use num::{bigint::Sign, BigInt, BigUint, One, Zero};
use rand::{self, RngCore};

pub mod chal18;
pub mod chal23;
pub mod chal24;
pub mod chal28;
pub mod chal29;
pub mod chal30;
pub mod chal31;
pub mod chal36;
pub mod chal38;
pub mod chal39;
pub mod chal40;
pub mod chal43;
pub mod chal46;
pub mod chal47;

pub fn random_bytes(size: u32) -> Vec<u8> {
    let mut bytes = vec![0 as u8; size as usize];
    rand::thread_rng().fill_bytes(&mut bytes[..]);
    bytes
}

pub fn random_bytes_array(arr: &mut [u8]) {
    for elem in arr.iter_mut() {
        *elem = rand::random::<u8>();
    }
}

pub trait MAC {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn verify(&self, msg: &[u8], tag: &[u8]) -> bool;
}

// SRP client trait
pub trait SrpClient {
    /// intiate kex by outputing (email, A = g ^a)
    fn init(&mut self) -> (String, BigUint);
    /// perform kex upon receiving server side ephemeral (salt, B = kv + g^b)
    /// outputs HMAC tag for verification
    fn kex(&mut self, salt: &[u8], B: &BigUint) -> Vec<u8>;
}

#[allow(clippy::many_single_char_names)]
/// returns a^-1 mod n (if exists)
pub fn mod_inv(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = BigInt::from_biguint(Sign::Plus, n.clone());
    let mut new_r = BigInt::from_biguint(Sign::Plus, a.clone());

    fn t_transition(t: &mut BigInt, new_t: &mut BigInt, q: &BigInt) {
        let new_t_val = t.clone() - q * new_t.clone();
        *t = new_t.clone();
        *new_t = new_t_val;
    }
    fn r_transition(r: &mut BigInt, new_r: &mut BigInt, q: &BigInt) {
        let new_r_val = r.clone() - q * new_r.clone();
        *r = new_r.clone();
        *new_r = new_r_val;
    }
    while new_r != BigInt::zero() {
        let q = &r / &new_r;
        t_transition(&mut t, &mut new_t, &q);
        r_transition(&mut r, &mut new_r, &q);
    }

    if r > BigInt::one() {
        // gcd(a, n) != 1, not invertible
        return None;
    }

    if t < BigInt::zero() {
        t += BigInt::from_biguint(Sign::Plus, n.clone());
    }

    Some(t.to_biguint().unwrap())
}

#[allow(clippy::many_single_char_names)]
/// returns (a-b) mod n
pub fn mod_sub(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    if a >= b {
        a - b
    } else {
        a + n - b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_modinv() {
        assert_eq!(
            mod_inv(
                &BigUint::parse_bytes(b"17", 10).unwrap(),
                &BigUint::parse_bytes(b"3120", 10).unwrap()
            )
            .unwrap(),
            BigUint::parse_bytes(b"2753", 10).unwrap()
        );
    }

    use num::Zero;
    #[test]
    fn test_modsub() {
        let n = BigUint::parse_bytes(b"13", 10).unwrap();
        assert_eq!(
            mod_sub(
                &BigUint::parse_bytes(b"7", 10).unwrap(),
                &BigUint::parse_bytes(b"3", 10).unwrap(),
                &n
            ),
            BigUint::parse_bytes(b"4", 10).unwrap()
        );
        assert_eq!(
            mod_sub(
                &BigUint::parse_bytes(b"3", 10).unwrap(),
                &BigUint::parse_bytes(b"7", 10).unwrap(),
                &n
            ),
            BigUint::parse_bytes(b"9", 10).unwrap()
        );
        assert_eq!(
            mod_sub(
                &BigUint::parse_bytes(b"12", 10).unwrap(),
                &BigUint::parse_bytes(b"12", 10).unwrap(),
                &n
            ),
            BigUint::zero()
        );
    }
}
