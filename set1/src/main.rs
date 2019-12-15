use std::collections::HashMap;
use std::str;
mod base64;
mod xor;

fn main() {
    println!("Challenge 3: Single-byte XOR Cipher");
    println!(
        "Decrypted Msg candidates: {:?}",
        single_byte_xor_decipher(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        )
    );
    println!("===================================");
}

fn single_byte_xor_decipher(cipertext: &str) -> String {
    let letter_freq = " etaoinshrdlucmfwypvbgkjqxz".as_bytes();
    let mut occurance = HashMap::new();
    let cipertext_bytes: Vec<u8> = base64::hex_to_bytes(cipertext).unwrap();
    for b in cipertext_bytes.into_iter() {
        let ctr = occurance.entry(b).or_insert(0);
        *ctr += 1;
    }

    let mut count: Vec<(&u8, &u32)> = occurance.iter().collect();
    count.sort_by(|a, b| b.1.cmp(a.1)); // compare ctr: u32 in descending order

    let xor_candidate =
        base64::bytes_to_hex(&vec![letter_freq[0] ^ count[0].0; cipertext.len() / 2]);
    let decrypted_hex_str = xor::fixed_xor(cipertext, &xor_candidate).unwrap();
    let decrypted_bytes = base64::hex_to_bytes(&decrypted_hex_str).unwrap();
    String::from_utf8(decrypted_bytes).unwrap()
}
