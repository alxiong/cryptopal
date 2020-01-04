use anyhow::anyhow;
use anyhow::Result;

/// Convert hex string to raw bytes `Vec<u8>`, return anyhow::Error if contains
/// invalid charater (not 0~9a~f)
pub fn hexstr_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let chars: Vec<char> = hex.chars().collect();
    match chars.len() % 2 {
        0 => {
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
        _ => Err(anyhow!("Wrong hex string length, should be even")),
    }
}

/// Convert raw bytes `[u8]` to hex string
pub fn bytes_to_hexstr(bytes: &[u8]) -> String {
    let mut hex_bytes: Vec<u8> = vec![];
    for byte in bytes.iter() {
        hex_bytes.push(byte >> 4);
        hex_bytes.push(byte & 0xf);
    }
    let chars: Vec<char> = hex_bytes
        .iter()
        .map(|num| std::char::from_digit(*num as u32, 16).unwrap())
        .collect();
    chars.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes() {
        let b: Vec<u8> = vec![18, 52, 86, 120, 144, 171, 205, 239];
        assert_eq!(hexstr_to_bytes("1234567890abcdef").unwrap(), b);

        assert!(hexstr_to_bytes("1ab").is_err());
    }

    #[test]
    fn bytes_to_hex() {
        let b: Vec<u8> = vec![18, 52, 86, 120, 144, 171, 205, 239];
        assert_eq!(bytes_to_hexstr(&b), "1234567890abcdef");
    }
}
