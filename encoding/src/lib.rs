#![deny(clippy::all)]
pub mod base64;
pub mod hex;

use anyhow::Result;
use base64::*;

pub fn hex_to_base64(hex: &str) -> Result<Base64> {
    let bytes = hex::hexstr_to_bytes(&hex)?;
    Ok(Base64::from(&bytes[..]))
}

pub fn base64_to_hex(b64: Base64) -> String {
    hex::bytes_to_hexstr(&b64.as_bytes()[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hex_to_base64_chal1() {
        assert_eq!(
            hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap(),
            Base64::from_str("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t").unwrap()
        );
    }

    #[test]
    fn test_base64_to_hex() {
        assert_eq!(
            base64_to_hex(Base64::from_str("Jk8DCkkcC3hFMQIEC0EbAVIqCFZBO1IdBgZUVA4QTgUWSR4QJwwRTWM=").unwrap()),
            String::from("264f030a491c0b78453102040b411b01522a0856413b521d060654540e104e0516491e10270c114d63"),
        );
    }
}
