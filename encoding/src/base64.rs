use anyhow::{anyhow, Result};
use std::collections::HashMap;
pub use std::str::FromStr;

static BASE64_CHAR_SET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

#[derive(Debug, PartialEq)]
pub struct Base64 {
    value: String,
}

impl FromStr for Base64 {
    type Err = anyhow::Error;
    /// Validate and construct a `Base64` type from a base64 string,
    /// if the string `s` contains invalid (non-base64) character, then `anyhow::Error`
    /// will be returned, otherwise returns `Ok(Base64)`.
    ///
    /// # Example
    ///
    /// ```
    /// use encoding::base64::*;
    ///
    /// assert!(Base64::from_str(&"winv023 df-@#$").is_err());
    /// assert!(Base64::from_str(&"JIvenhd932+/dfe").is_ok());
    /// ```
    fn from_str(s: &str) -> Result<Base64, Self::Err> {
        if s.chars().filter(|&c| BASE64_CHAR_SET.contains(c)).count() != s.len() {
            Err(anyhow!("Invalid base64 String to create a new Base64 type"))
        } else {
            Ok(Base64 {
                value: String::from(s),
            })
        }
    }
}

impl Base64 {
    /// Convert base64 to raw bytes `Vec<u8>`
    ///
    /// # Example
    ///
    /// ```
    /// use encoding::base64::*;
    /// assert_eq!(Base64::from_str("Jk8DTWM=").unwrap().as_bytes(), vec![38, 79, 3, 77, 99]);
    /// ```
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut table: HashMap<char, u8> = HashMap::new();
        for (i, c) in BASE64_CHAR_SET
            .chars()
            .collect::<Vec<_>>()
            .iter()
            .enumerate()
        {
            table.insert(*c, i as u8);
        }

        let sextets: Vec<_> = self
            .value
            .chars()
            .filter(|&c| c != '=')
            .map(|c| table.get(&c).unwrap())
            .collect();

        sextets[..]
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
            .flatten()
            .collect::<Vec<u8>>()
    }
}

impl From<&[u8]> for Base64 {
    /// Converts a raw bytes `&[u8]` to `Base64`
    ///
    /// # Examples
    ///
    /// ```
    /// use encoding::base64::Base64;
    ///
    /// let b: Vec<u8> = vec![114, 117, 115, 116, 32, 105, 115, 32, 99, 111, 111, 108];
    /// let b64 = Base64::from(&b[..]);
    /// ```
    fn from(bytes: &[u8]) -> Self {
        let mut b64 = String::from(""); // if b.len() == 0, should return Ok("")
        let table: Vec<char> = BASE64_CHAR_SET.chars().collect();
        for chunk in bytes.chunks_exact(3) {
            let first_sextet = chunk[0] >> 2;
            let second_sextet = ((chunk[0] & 0x3) << 4) | (chunk[1] >> 4);
            let third_sextet = ((chunk[1] & 0xf) << 2) | (chunk[2] >> 6);
            let fourth_sextet = chunk[2] & 0x3f;
            b64.push(table[first_sextet as usize]);
            b64.push(table[second_sextet as usize]);
            b64.push(table[third_sextet as usize]);
            b64.push(table[fourth_sextet as usize]);
        }

        let remainder: &[u8] = bytes.chunks_exact(3).remainder();
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

        Base64::from_str(&b64).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_base64_from_string() {
        assert!(Base64::from_str("winv023 df-@#$").is_err());
        assert!(Base64::from_str("JIvenhd932+/dfe").is_ok());
    }

    #[test]
    fn base64_from_bytes() {
        let b: Vec<u8> = vec![114, 117, 115, 116, 32, 105, 115, 32, 99, 111, 111, 108];
        assert_eq!(
            Base64::from(&b[..]),
            Base64::from_str(&String::from("cnVzdCBpcyBjb29s")).unwrap()
        );
    }

    #[test]
    fn bytes_from_base64() {
        assert_eq!(
            Base64::from_str("Jk8DCkkcC3hFMQIEC0EbAVIqCFZBO1IdBgZUVA4QTgUWSR4QJwwRTWM")
                .unwrap()
                .as_bytes(),
            vec![
                38, 79, 3, 10, 73, 28, 11, 120, 69, 49, 2, 4, 11, 65, 27, 1, 82, 42, 8, 86, 65, 59,
                82, 29, 6, 6, 84, 84, 14, 16, 78, 5, 22, 73, 30, 16, 39, 12, 17, 77, 99
            ]
        );
    }
}
