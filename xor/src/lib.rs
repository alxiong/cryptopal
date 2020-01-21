#![deny(clippy::all)]
use anyhow::{anyhow, Result};
use encoding::hex;

pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    if a.len() != b.len() {
        Err(anyhow!(
            "Invalid input, XOR only on two equal length vector"
        ))
    } else {
        Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
    }
}

/// XOR operation on two hex string of the same length.
pub fn fixed_xor(hex1: &str, hex2: &str) -> Result<String> {
    let b1 = hex::hexstr_to_bytes(&hex1)?;
    let b2 = hex::hexstr_to_bytes(&hex2)?;
    let result_bytes = xor(&b1, &b2)?;
    Ok(hex::bytes_to_hexstr(&result_bytes))
}

/// XOR operation on `msg` (hex str) with repeating `key` (also hex str)
pub fn repeating_xor(msg: &str, key: &str) -> String {
    let mut result = String::new();
    for i in 0..(msg.len() / key.len()) {
        result.push_str(&fixed_xor(&msg[i * key.len()..(i + 1) * key.len()], &key[..]).unwrap());
    }
    // dealing with remainder
    let remainder_len = msg.len() % key.len();
    result.push_str(&fixed_xor(&msg[msg.len() - remainder_len..], &key[0..remainder_len]).unwrap());

    result
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
            )
            .unwrap(),
            String::from("746865206b696420646f6e277420706c6179"),
        );
        assert!(fixed_xor("12", "3").is_err());
    }

    #[test]
    fn test_repeating_xor() {
        let msg_hex = hex::bytes_to_hexstr(
            &"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes(),
        );
        let key_hex = hex::bytes_to_hexstr(&b"ICE".to_vec());
        assert_eq!(
            repeating_xor(&msg_hex, &key_hex),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }
}
