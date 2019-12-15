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
}
