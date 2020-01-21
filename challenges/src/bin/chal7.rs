use encoding::base64::*;
use openssl::symm::{self, Cipher};
use std::fs;

fn main() {
    println!("🔓 Challenge 7");
    let ct_base64: String = fs::read_to_string("challenges/data/chal7.txt")
        .unwrap()
        .lines()
        .collect();
    let ct = Base64::from_str(&ct_base64).unwrap().as_bytes();
    let cipher = Cipher::aes_128_ecb();
    let iv: Vec<u8> = vec![];
    let pt = symm::decrypt(cipher, b"YELLOW SUBMARINE", Some(&iv), &ct).unwrap_or_default();
    println!("Decrypted msg: {:?}", String::from_utf8(pt).unwrap());
}
