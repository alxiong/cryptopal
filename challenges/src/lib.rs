#![deny(clippy::all)]
#![allow(dead_code, non_snake_case)]
#![feature(proc_macro_hygiene, decl_macro)]

use num::BigUint;
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
