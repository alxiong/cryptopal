#![deny(clippy::all)]
#![allow(dead_code)]

use rand::{self, RngCore};

pub mod chal18;
pub mod chal23;
pub mod chal24;
pub mod chal28;
pub mod chal29;
pub mod chal30;

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
