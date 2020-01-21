use cryptanalysis::vigenere;
use encoding::base64::*;
use encoding::hex;
use std::fs;

fn main() {
    println!("🔓 Challenge 6");
    let ct_base64: String = fs::read_to_string("challenges/data/chal6.txt")
        .unwrap()
        .lines()
        .collect();
    let ct_bytes: Vec<u8> = Base64::from_str(&ct_base64).unwrap().as_bytes();
    let key = vigenere::extract_key(&ct_bytes);
    let pt_hex = xor::repeating_xor(
        &hex::bytes_to_hexstr(&ct_bytes),
        &hex::bytes_to_hexstr(&key),
    );
    println!(
        "Decrypted msg: {}",
        String::from_utf8(hex::hexstr_to_bytes(&pt_hex).unwrap()).unwrap_or_default()
    );
    println!("⚠️ NOTICE that the decrypted text are not entirely right, but already readable. Those minor errors come from an imperfect `break_single_byte_xor` scoring algorithm");
}
