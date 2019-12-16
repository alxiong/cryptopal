#![allow(dead_code)]
use std::collections::HashMap;
use std::{fs, io, str};
mod base64;
mod vigenere;
mod xor;

fn main() {
    // chal_3();
    // chal_4();
    chal_6();
}
fn chal_3() {
    println!("Challenge 3: Single-byte XOR Cipher");
    println!(
        "Decrypted Msg candidates: {:?}",
        single_byte_xor_decipher(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
            0
        )
    );
    println!("===================================");
}
fn chal_4() {
    println!("Challenge 4: Detect single-character XOR");
    let ciphertext_hex = fs::read_to_string("data/chal4.txt").unwrap();
    println!(
        "Decrypted msg is: {}",
        single_xor_detect(&ciphertext_hex).unwrap()
    );
    println!("===================================");
}
fn chal_6() {
    println!("CHallenge 6: Break repeating-key XOR");
    let ct_base64: String = fs::read_to_string("data/chal6.txt").unwrap();
    break_repeating_xor(&ct_base64);
    println!("===================================");
}

fn single_byte_xor_decipher(cipertext: &str, freq_letter_used: usize) -> String {
    let letter_freq = " etaoinshrdlucmfwypvbgkjqxz".as_bytes();
    let mut occurance = HashMap::new();
    let cipertext_bytes: Vec<u8> = base64::hex_to_bytes(cipertext).unwrap();
    for b in cipertext_bytes.into_iter() {
        let ctr = occurance.entry(b).or_insert(0);
        *ctr += 1;
    }

    let mut count: Vec<(&u8, &u32)> = occurance.iter().collect();
    count.sort_by(|a, b| b.1.cmp(a.1)); // compare ctr: u32 in descending order

    let xor_candidate = base64::bytes_to_hex(&vec![
        letter_freq[freq_letter_used] ^ count[0].0;
        cipertext.len() / 2
    ]);

    let decrypted_hex_str = xor::fixed_xor(cipertext, &xor_candidate).unwrap();
    let decrypted_bytes = base64::hex_to_bytes(&decrypted_hex_str).unwrap();
    String::from_utf8(decrypted_bytes).unwrap_or_default()
}

fn single_xor_detect(ciphertext: &str) -> io::Result<String> {
    let mut decrypted_str = String::new();

    for line in ciphertext.lines() {
        let decrypted_line = single_byte_xor_decipher(line, 0);
        if !decrypted_line.is_empty()
            && decrypted_line
                .chars()
                .all(|c| c.is_alphanumeric() || c.is_whitespace())
        {
            decrypted_str.push_str(&decrypted_line);
            decrypted_str.push('\n');
        }
    }
    Ok(decrypted_str)
}

fn break_repeating_xor(ct: &str) {
    let ct_base64: String = ct.lines().collect();
    let key_size = vigenere::key_size(&ct_base64);
    let transposed_block: Vec<_> =
        vigenere::transpose_block(vigenere::into_block_lossy(&ct_base64, key_size));

    println!("{}", key_size);
}
