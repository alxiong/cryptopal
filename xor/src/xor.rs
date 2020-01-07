#![allow(dead_code)]
use encoding::base64;
use std::collections::HashMap;
use std::iter::FromIterator;

fn fixed_xor(hex1: &str, hex2: &str) -> Result<String, &'static str> {
    if hex1.len() != hex2.len() {
        return Err("two hex string should have the same length");
    }

    let xor: Vec<_> = hex1
        .chars()
        .zip(hex2.chars())
        .map(|(a, b)| a.to_digit(16).unwrap() ^ b.to_digit(16).unwrap())
        .map(|digit| format!("{:x}", digit))
        .collect();

    Ok(String::from_iter(xor))
}

fn repeating_xor(msg: &str, key: &str) -> String {
    let mut xor: String = String::new();

    for i in 0..(msg.len() / key.len()) {
        xor.push_str(&fixed_xor(&msg[i * key.len()..(i + 1) * key.len()], &key[..]).unwrap());
    }
    // dealing with remainder
    let remainder_len = msg.len() % key.len();
    xor.push_str(&fixed_xor(&msg[msg.len() - remainder_len..], &key[0..remainder_len]).unwrap());
    xor
}

pub fn break_single_byte_xor(ciphertext: &str) -> String {
    let letter_freq = " etaoinshrdlucmfwypvbgkjqxz".as_bytes();
    let mut occurance = HashMap::new();
    let cipertext_bytes: Vec<u8> = base64::hex_to_bytes(ciphertext).unwrap();
    for b in cipertext_bytes.into_iter() {
        let ctr = occurance.entry(b).or_insert(0);
        *ctr += 1;
    }

    let mut count: Vec<(&u8, &u32)> = occurance.iter().collect();
    count.sort_by(|a, b| b.1.cmp(a.1)); // compare ctr: u32 in descending order

    let xor_candidate =
        base64::bytes_to_hex(&vec![letter_freq[0] ^ count[0].0; ciphertext.len() / 2]);

    let decrypted_hex_str = fixed_xor(ciphertext, &xor_candidate).unwrap();
    let decrypted_bytes = base64::hex_to_bytes(&decrypted_hex_str).unwrap();
    String::from_utf8(decrypted_bytes).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_xor() {
        assert_eq!(
            fixed_xor(
                "1c0111001f010100061a024b53535009181c",
                "686974207468652062756c6c277320657965"
            ),
            Ok(String::from("746865206b696420646f6e277420706c6179")),
        );
        assert_eq!(
            fixed_xor("12", "3"),
            Err("two hex string should have the same length"),
        );
    }

    #[test]
    fn test_repeating_xor() {
        let msg_hex = base64::bytes_to_hex(
            &"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes()
                .to_vec(),
        );
        let key_hex = base64::bytes_to_hex(&"ICE".as_bytes().to_vec());

        assert_eq!(
            repeating_xor(&msg_hex, &key_hex),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        );
    }

    #[test]
    fn test_single_byte_xor_decipher() {
        assert_eq!(
            break_single_byte_xor(
                &"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
            ),
            "Cooking MC's like a pound of bacon"
        );
    }
}
