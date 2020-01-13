#![allow(dead_code)]
use super::{from_blocks, into_blocks, padding, random_bytes_array, Cipher};
use openssl::symm::{Cipher as SslCipher, Crypter as SslCrypter, Mode};
use xor;

#[allow(non_camel_case_types)]
pub struct AES_128_CBC {}

impl AES_128_CBC {
    /// Instantiate a new `AES_128_CBC` cipher with an all-zero `iv`.
    pub fn new() -> AES_128_CBC {
        AES_128_CBC {}
    }

    /// Validate whether `blocks` is truncated into a list of 128-bit(16-byte) block.
    fn validate_block(blocks: &Vec<Vec<u8>>) {
        for block in blocks.iter() {
            if block.len() != 16 {
                panic!("Invalid plaintext, not 128-bit block");
            }
        }
    }

    /// Add padding to the trailing block.
    fn add_padding(blocks: &mut Vec<Vec<u8>>) {
        let result = padding::add(blocks, 16);
        if result.is_err() {
            panic!("failed to add padding, internal bug");
        }
    }

    /// Remove trailing padding, mostly used on decrypted blocks
    fn remove_padding(blocks: &mut Vec<Vec<u8>>) {
        let result = padding::remove(blocks, 16);
        if result.is_err() {
            panic!("failed to remove padding, internal bug");
        }
    }
}

impl Cipher for AES_128_CBC {
    fn encrypt(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        // format msg into 2D vector blocks
        let mut msg_block = into_blocks(msg, 16);
        // Pad and validate msg blocks
        Self::add_padding(&mut msg_block);
        Self::validate_block(&msg_block);

        let mut ct: Vec<Vec<u8>> = vec![Vec::new(); msg_block.len()];
        let mut iv = [0 as u8; 16];
        random_bytes_array(&mut iv);

        let mut last: Vec<u8> = iv.to_vec();
        let mut encrypter =
            SslCrypter::new(SslCipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
        encrypter.pad(false); // disable padding from ECB encryption, only use it as a pure AES Encryption

        // CBC encrypt
        for i in 0..(*msg_block).len() {
            ct[i] = vec![0; 32]; // avoid assertion
            let mut count = encrypter
                .update(&xor::xor(&last, &(*msg_block)[i]).unwrap(), &mut ct[i])
                .unwrap();
            count += encrypter.finalize(&mut ct[i][count..]).unwrap();
            ct[i].truncate(count);

            last = ct[i].clone();
        }
        [iv.to_vec(), from_blocks(&ct)].concat()
    }

    fn decrypt(&self, key: &[u8], ct: &[u8]) -> Vec<u8> {
        // format ciphertext to 2D vector
        let mut iv_ct_blocks = into_blocks(&ct, 16);
        Self::validate_block(&iv_ct_blocks);
        let ct_blocks = iv_ct_blocks.split_off(1); // chop off the first 16-byte iv

        // CBC decrypt
        let mut pt: Vec<Vec<u8>> = vec![Vec::new(); ct_blocks.len()];
        let mut last = &iv_ct_blocks[0];
        let mut decrypter =
            SslCrypter::new(SslCipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
        decrypter.pad(false); // disable padding from aes_128_ecb

        for i in 0..(*ct_blocks).len() {
            pt[i] = vec![0; 32];
            let mut count = decrypter.update(&ct_blocks[i], &mut pt[i]).unwrap();
            count += decrypter.finalize(&mut pt[i][count..]).unwrap();
            pt[i].truncate(count);
            pt[i] = xor::xor(&last, &pt[i]).unwrap();

            last = &ct_blocks[i];
        }

        // remove padding
        Self::remove_padding(&mut pt);
        from_blocks(&pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_correctness() {
        let cipher = AES_128_CBC::new();
        let msg1 = "Privacy".as_bytes();
        let msg2 = "Privacy is necessary".as_bytes();
        let key = "i am pied piper!".as_bytes();

        // test correctness of the cipher, i.e. decryption also works
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg1)), msg1);
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg2)), msg2);
    }
}
