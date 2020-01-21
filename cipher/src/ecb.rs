use super::Cipher;
use openssl::symm::{self, Cipher as SslCipher};

#[allow(non_camel_case_types)]
#[derive(Default)]
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
        let msg1 = b"Privacy".to_vec();
        let msg2 = b"Privacy is necessary".to_vec();
        let msg3 = b"Privacy is necessary for an open society in the electronic age".to_vec();
        let key = b"i am pied piper!".to_vec();
        let cipher = AES_128_ECB::new();
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg1)), msg1);
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg2)), msg2);
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg3)), msg3);
    }
}
