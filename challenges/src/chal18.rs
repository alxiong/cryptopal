use super::random_bytes;
use cipher::{ctr::AES_128_CTR, Cipher};
use encoding::base64::*;
use std::fs;

#[derive(Default)]
pub struct Key(Vec<u8>);
impl Key {
    pub fn new() -> Key {
        Key(random_bytes(16))
    }

    pub fn successive_encryption(&self) -> Vec<Vec<u8>> {
        let pt_str = fs::read_to_string("challenges/data/chal19.txt").unwrap();
        let all_pt: Vec<Vec<u8>> = pt_str
            .lines()
            .collect::<Vec<_>>()
            .iter()
            .map(|s| Base64::from_str(s).unwrap().as_bytes())
            .collect();

        let ctr_cipher = AES_128_CTR::new_with_nonce(0);
        let mut all_ct: Vec<Vec<u8>> = vec![];
        for pt in all_pt.iter() {
            all_ct.push(ctr_cipher.encrypt(&self.0, pt));
        }
        all_ct
    }
}
