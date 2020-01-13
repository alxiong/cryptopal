use cipher::{self, Mode};
use encoding::base64::Base64;
use std::fs;

fn main() {
    println!("🔓 Challenge 10");
    let cbc_cipher = cipher::new(Mode::CBC);
    let ct_base64: String = fs::read_to_string("challenges/data/chal10.txt")
        .unwrap()
        .lines()
        .collect();
    let ct_bytes = Base64::from_str(&ct_base64).unwrap().as_bytes();
    let key = "YELLOW SUBMARINE".as_bytes();

    let pt = cbc_cipher.decrypt(&key, &ct_bytes);
    println!("decrypted message: \n{:?}", String::from_utf8(pt).unwrap());
}
