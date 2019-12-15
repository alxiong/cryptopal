#![allow(dead_code)]
use std::char;

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, &str> {
    let chars: Vec<char> = hex.chars().collect();
    if chars.len() % 2 != 0 {
        return Err("Wrong hex string length, should be even");
    }

    let bytes = chars
        .chunks_exact(2)
        .map(|chunk| {
            let first_byte = chunk[0].to_digit(16).unwrap();
            let second_byte = chunk[1].to_digit(16).unwrap();
            (first_byte << 4 | second_byte) as u8
        })
        .collect();
    Ok(bytes)
}

pub fn bytes_to_hex(bytes: &Vec<u8>) -> String {
    let mut hex_bytes: Vec<u8> = vec![];
    for byte in bytes.iter() {
        hex_bytes.push(byte >> 4);
        hex_bytes.push(byte & 0xf);
    }
    let chars: Vec<char> = hex_bytes
        .iter()
        .map(|num| char::from_digit(*num as u32, 16).unwrap())
        .collect();
    let hex_string: String = chars.iter().collect();
    hex_string
}

fn bytes_to_base64(b: Vec<u8>) -> String {
    let mut b64 = String::from(""); // if b.len() == 0, should return Ok("")
    let table: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        .chars()
        .collect();
    for chunk in b.chunks_exact(3) {
        let first_sextet = chunk[0] >> 2;
        let second_sextet = ((chunk[0] & 0x3) << 4) | (chunk[1] >> 4);
        let third_sextet = ((chunk[1] & 0xf) << 2) | (chunk[2] >> 6);
        let fourth_sextet = chunk[2] & 0x3f;
        b64.push(table[first_sextet as usize]);
        b64.push(table[second_sextet as usize]);
        b64.push(table[third_sextet as usize]);
        b64.push(table[fourth_sextet as usize]);
    }

    let remainder: &[u8] = b.chunks_exact(3).remainder();
    match remainder.len() {
        1 => {
            let first_sextet = remainder[0] >> 2;
            let second_sextet = (remainder[0] & 0x3) << 4;
            b64.push(table[first_sextet as usize]);
            b64.push(table[second_sextet as usize]);
            b64.push_str("==");
        }
        2 => {
            let first_sextet = remainder[0] >> 2;
            let second_sextet = ((remainder[0] & 0x3) << 4) | (remainder[1] >> 4);
            let third_sextet = (remainder[1] & 0xf) << 2;
            b64.push(table[first_sextet as usize]);
            b64.push(table[second_sextet as usize]);
            b64.push(table[third_sextet as usize]);
            b64.push_str("=");
        }
        _ => (),
    }

    b64
}
fn hex_to_base64(hex: &str) -> Result<String, &str> {
    let b = hex_to_bytes(hex)?;
    Ok(bytes_to_base64(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes() {
        let b: Vec<u8> = vec![18, 52, 86, 120, 144, 171, 205, 239];
        assert_eq!(hex_to_bytes("1234567890abcdef"), Ok(b));

        let a = hex_to_bytes("1ab");
        assert_eq!(a, Err("Wrong hex string length, should be even"));
    }

    #[test]
    fn test_hex_to_base64() {
        assert_eq!(
            hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
            Ok(String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))
        );
    }

    #[test]
    fn test_bytes_to_hex() {
        let b: Vec<u8> = vec![18, 52, 86, 120, 144, 171, 205, 239];
        assert_eq!(bytes_to_hex(&b), "1234567890abcdef");
    }
}
