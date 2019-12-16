use crate::base64;
use std::iter::FromIterator;

pub fn fixed_xor(hex1: &str, hex2: &str) -> Result<String, &'static str> {
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

// key and msg are not hex string slice, but the actual content
pub fn repeating_xor(msg: &str, key: &str) -> String {
    let msg_hex = base64::bytes_to_hex(&msg.as_bytes().to_vec());
    let key_hex = base64::bytes_to_hex(&key.as_bytes().to_vec());
    let mut xor: String = String::new();

    for i in 0..(msg_hex.len() / key_hex.len()) {
        xor.push_str(
            &fixed_xor(
                &msg_hex[i * key_hex.len()..(i + 1) * key_hex.len()],
                &key_hex[..],
            )
            .unwrap(),
        );
    }
    // dealing with remainder
    let remainder_len = msg_hex.len() % key_hex.len();
    xor.push_str(
        &fixed_xor(
            &msg_hex[msg_hex.len() - remainder_len..],
            &key_hex[0..remainder_len],
        )
        .unwrap(),
    );
    xor
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
        assert_eq!(
            repeating_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        );
    }
}
