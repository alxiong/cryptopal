use cipher::{self, cbc::AES_128_CBC, Cipher};
use encoding::base64::Base64;
use std::fs;

fn main() {
    println!("🔓 Challenge 10");
    let cipher = AES_128_CBC::new();
    let ct_base64: String = fs::read_to_string("challenges/data/chal10.txt")
        .unwrap()
        .lines()
        .collect();
    let ct_bytes = Base64::from_str(&ct_base64).unwrap().as_bytes();
    let ct_blocks = cipher::into_blocks(&ct_bytes, 16);
    let key = "YELLOW SUBMARINE".as_bytes().to_vec();

    let pt = cipher.decrypt(&key, &Box::from(ct_blocks));
    println!("decrypted message: \n{:?}", cipher::from_blocks(*pt));
}
