use super::Cipher;
use openssl::symm::{self, Cipher as SslCipher};

#[allow(non_camel_case_types)]
pub struct AES_128_ECB {}

impl AES_128_ECB {
    pub fn new() -> AES_128_ECB {
        AES_128_ECB {}
    }
}

impl Cipher for AES_128_ECB {
    // NOTE: ideally the msg shall be read-only `&[u8]`, but that would mismatch the Cipher trait
    fn encrypt(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        symm::encrypt(SslCipher::aes_128_ecb(), key, None, msg).unwrap()
    }

    fn decrypt(&self, key: &[u8], ct: &[u8]) -> Vec<u8> {
        symm::decrypt(SslCipher::aes_128_ecb(), key, None, &ct[..]).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ecb_correctness() {
        let msg1 = "Privacy".as_bytes().to_vec();
        let msg2 = "Privacy is necessary".as_bytes().to_vec();
        let msg3 = "Privacy is necessary for an open society in the electronic age"
            .as_bytes()
            .to_vec();
        let key = "i am pied piper!".as_bytes().to_vec();
        let cipher = AES_128_ECB::new();
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg1)), msg1);
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg2)), msg2);
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg3)), msg3);
    }
}
