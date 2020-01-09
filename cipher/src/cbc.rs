#![allow(dead_code)]
use super::{from_blocks, into_blocks, Cipher};
use openssl::symm::{Cipher as SslCipher, Crypter as SslCrypter, Mode};
use xor;

#[allow(non_camel_case_types)]
pub struct AES_128_CBC {
    iv: [u8; 16],
}

impl AES_128_CBC {
    /// Instantiate a new `AES_128_CBC` cipher with an all-zero `iv`.
    pub fn new(iv: &[u8; 16]) -> AES_128_CBC {
        AES_128_CBC { iv: *iv }
    }

    /// Validate whether `blocks` is truncated into a list of 128-bit(16-byte) block.
    fn validate_block(blocks: &Vec<Vec<u8>>) -> bool {
        for block in blocks.iter() {
            if block.len() != 16 {
                return false;
            }
        }
        true
    }

    /// Add padding to the trailing block.
    fn add_padding(blocks: &mut Vec<Vec<u8>>) {
        if Self::validate_block(&blocks) {
            // multiple of block size, add a dummy block
            blocks.push(vec![16 as u8; 16]);
        } else {
            // not multiple of block size
            if let Some(last_block) = blocks.last_mut() {
                *last_block = pad_block(&*last_block, 16);
            }
        }
    }

    /// Remove trailing padding, mostly used on decrypted blocks
    fn remove_padding(blocks: &mut Vec<Vec<u8>>) {
        if !Self::validate_block(&blocks) {
            panic!("try to remove padding from a non-multiple-block-size input");
        }

        let pad_len = *blocks.last().unwrap().last().unwrap();
        if pad_len == 16 {
            blocks.pop();
        } else {
            let last = blocks.last_mut().unwrap();
            last.truncate(16 - pad_len as usize);
        }
    }
}

impl Cipher for AES_128_CBC {
    fn encrypt(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        // format msg into 2D vector blocks
        let mut msg_block = into_blocks(msg, 16);
        // Pad and validate msg blocks
        Self::add_padding(&mut msg_block);
        if !Self::validate_block(&msg_block) {
            panic!("Invalid plaintext, not 128-bit block");
        }

        let mut ct: Vec<Vec<u8>> = vec![Vec::new(); msg_block.len()];
        let mut last = self.iv.to_vec();
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
        from_blocks(&ct)
    }

    fn decrypt(&self, key: &[u8], ct: &[u8]) -> Vec<u8> {
        // format ciphertext to 2D vector
        let ct_blocks = into_blocks(&ct, 16);

        // validate the ciphertext
        if !Self::validate_block(&ct_blocks) {
            panic!("Invalid ciphertext, not 128-bit block");
        }

        // CBC decrypt
        let mut pt: Vec<Vec<u8>> = vec![Vec::new(); ct_blocks.len()];
        let mut last = &self.iv.to_vec();
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

fn pad_block(block: &[u8], size: u8) -> Vec<u8> {
    let padding_len: u8 = size - block.len() as u8;
    let mut padded = block.to_vec();
    padded.append(&mut vec![padding_len; padding_len as usize]);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding() {
        assert_eq!(
            pad_block(&"YELLOW SUBMARINE".as_bytes(), 20 as u8),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }

    #[test]
    fn cbc_correctness() {
        let cipher = AES_128_CBC::new(&[0 as u8; 16]);
        let msg1 = "Privacy".as_bytes().to_vec();
        let msg2 = "Privacy is necessary".as_bytes().to_vec();
        let msg3 = "Privacy is necessary for an open society in the electronic age"
            .as_bytes()
            .to_vec();
        let key = "i am pied piper!".as_bytes().to_vec();

        // test encrypt is correctly implemented by comparing to the ciphertext produced by the OpenSSL lib
        assert_eq!(
            openssl::symm::encrypt(SslCipher::aes_128_cbc(), &key, Some(&vec![0; 16]), &msg1)
                .unwrap(),
            cipher.encrypt(&key, &msg1)
        );
        // test correctness of the cipher, i.e. decryption also works
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg1)), msg1);
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg2)), msg2);
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg3)), msg3);
    }
}