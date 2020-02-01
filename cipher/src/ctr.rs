use super::{from_blocks, Cipher};
use openssl::symm::{Cipher as SslCipher, Crypter as SslCrypter, Mode};
use rand;

#[allow(non_camel_case_types)]
#[derive(Default)]
pub struct AES_128_CTR {
    nonce: u64,
}

impl AES_128_CTR {
    pub fn new() -> AES_128_CTR {
        AES_128_CTR {
            nonce: rand::random::<u64>(),
        }
    }

    pub fn new_with_nonce(nonce: u64) -> AES_128_CTR {
        AES_128_CTR { nonce }
    }

    // format=64 bit unsigned little endian nonce, 64 bit little endian block count (byte count / 16)
    fn format_counter(&self, ctr: u64) -> Vec<u8> {
        [self.nonce.to_le_bytes(), ctr.to_le_bytes()].concat()
    }
}

impl Cipher for AES_128_CTR {
    fn encrypt(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        if key.len() != 16 {
            panic!("Invalid key length, should be 16 bytes");
        }

        let mut ct: Vec<Vec<u8>> = vec![];
        let mut encrypter = SslCrypter::new(SslCipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
        encrypter.pad(false);

        for (ctr, msg_block) in msg.chunks(16).enumerate() {
            let mut key_stream = vec![0 as u8; 32];
            let mut count = encrypter
                .update(&self.format_counter(ctr as u64), &mut key_stream[..])
                .unwrap();
            count += encrypter.finalize(&mut key_stream[count..]).unwrap();
            key_stream.truncate(count);
            key_stream.truncate(msg_block.len());

            ct.push(xor::xor(&key_stream[..], &msg_block).unwrap());
        }

        from_blocks(&ct)
    }

    fn decrypt(&self, key: &[u8], ct: &[u8]) -> Vec<u8> {
        let mut pt: Vec<Vec<u8>> = vec![];
        let mut encrypter = SslCrypter::new(SslCipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
        encrypter.pad(false);

        for (ctr, ct_block) in ct.chunks(16).enumerate() {
            let mut key_stream = vec![0 as u8; 32];
            let mut count = encrypter
                .update(&self.format_counter(ctr as u64), &mut key_stream[..])
                .unwrap();
            count += encrypter.finalize(&mut key_stream[count..]).unwrap();
            key_stream.truncate(count);
            key_stream.truncate(ct_block.len());

            pt.push(xor::xor(&key_stream[..], &ct_block).unwrap());
        }

        from_blocks(&pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ctr_correctness() {
        let cipher = AES_128_CTR::new();
        let msg1 = b"Privacy".to_vec();
        let msg2 = b"Privacy is necessary".to_vec();
        let key = b"i am pied piper!".to_vec();

        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg1)), msg1);
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg2)), msg2);
    }
}
