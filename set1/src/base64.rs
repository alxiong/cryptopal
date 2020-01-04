#![allow(dead_code)]
use std::char;
use std::collections::HashMap;

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
    let table: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
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

fn base64_to_bytes(base64: &str) -> Result<Vec<u8>, &str> {
    if base64.len() % 4 != 0 {
        return Err("invalid base64 encoded string");
    }

    let mut table: HashMap<char, u8> = HashMap::new();
    let freq_vec: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .chars()
        .collect();
    for (i, c) in freq_vec.iter().enumerate() {
        table.insert(*c, i as u8);
    }

    let sextets: Vec<_> = base64
        .chars()
        .filter(|&c| c != '=')
        .map(|c| table.get(&c).unwrap())
        .collect();
    println!("sextets: {:?}", sextets);

    let result: Vec<_> = sextets[..]
        .chunks(4)
        .map(|chunk| {
            let first_octet = (chunk[0] << 2) + (chunk[1] >> 4 & 0x3 as u8);
            if chunk.len() > 2 {
                let second_octet = ((chunk[1] & 0xf) << 4) + (chunk[2] >> 2 & 0xf as u8);
                if chunk.len() > 3 {
                    let third_octet = ((chunk[2] & 0x3) << 6) + (chunk[3] & 0x3f);
                    return [first_octet, second_octet, third_octet].to_vec();
                }
                return [first_octet, second_octet].to_vec();
            }
            [first_octet].to_vec()
        })
        .collect();
    Ok(result.into_iter().flatten().collect::<Vec<_>>())
}

pub fn hex_to_base64(hex: &str) -> Result<String, &str> {
    let b = hex_to_bytes(hex)?;
    Ok(bytes_to_base64(b))
}

pub fn base64_to_hex(base64: &str) -> Result<String, &str> {
    let bytes = base64_to_bytes(&base64)?;
    Ok(bytes_to_hex(&bytes))
}

#[cfg(test)]
mod base64_tests {
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
    fn test_base64_to_hex() {
        assert_eq!(
            base64_to_hex("Jk8DCkkcC3hFMQIEC0EbAVIqCFZBO1IdBgZUVA4QTgUWSR4QJwwRTWM="),
            Ok(String::from("264f030a491c0b78453102040b411b01522a0856413b521d060654540e104e0516491e10270c114d63")),
        );
    }

    #[test]
    fn test_bytes_to_hex() {
        let b: Vec<u8> = vec![18, 52, 86, 120, 144, 171, 205, 239];
        assert_eq!(bytes_to_hex(&b), "1234567890abcdef");
    }
}
