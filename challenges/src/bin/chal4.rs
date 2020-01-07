use cryptanalysis::freq_analysis;
use encoding::hex;
use std::fs;

fn main() {
    println!("🔓 Challenge 4");
    let ct_hex = fs::read_to_string("challenges/data/chal4.txt").unwrap();
    for line in ct_hex.lines() {
        let pt = freq_analysis::break_single_byte_xor(&hex::hexstr_to_bytes(&line).unwrap());
        if !pt.is_empty() && pt.chars().all(|c| c.is_alphanumeric() || c.is_whitespace()) {
            println!("Decrypted line: {}", pt);
        }
    }
}
