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

pub fn fixed_xor(hex1: &str, hex2: &str) -> Result<String> {
    let b1 = hex::hexstr_to_bytes(&hex1)?;
    let b2 = hex::hexstr_to_bytes(&hex2)?;
    let result_bytes = xor(&b1, &b2)?;
    Ok(hex::bytes_to_hexstr(&result_bytes))
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
}
