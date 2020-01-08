#![allow(dead_code)]
use super::Cipher;
use openssl::symm::{Cipher as SslCipher, Crypter as SslCrypter, Mode};
use xor;

#[allow(non_camel_case_types)]
pub struct AES_128_CBC {
    iv: Vec<u8>,
}

impl AES_128_CBC {
    /// Instantiate a new `AES_128_CBC` cipher with an all-zero `iv`.
    pub fn new() -> AES_128_CBC {
        AES_128_CBC { iv: vec![0; 16] }
    }

    /// Validate whether `blocks` is truncated into a list of 128-bit(16-byte) block.
    fn validate_block(blocks: &Box<Vec<Vec<u8>>>) -> bool {
        for block in (*blocks).iter() {
            if block.len() != 16 {
                return false;
            }
        }
        true
    }

    /// Add padding to the trailing block.
    ///
    /// NOTE: current implementation allocates a new 2D vector on heap which seems wasteful.
    /// Improvement via reusing the original `blocks` might require changes in types/interface
    /// (i.e. `Box<Vec<Rc<Vec<u8>>>>`), which looks more abstruse.
    fn add_padding(blocks: &Box<Vec<Vec<u8>>>) -> Box<Vec<Vec<u8>>> {
        let mut padded: Vec<Vec<u8>> = *blocks.clone();
        if Self::validate_block(&blocks) {
            // multiple of block size, add a dummy block
            padded.push(vec![16 as u8; 16]);
        } else {
            // not multiple of block size
            if let Some(last_block) = (*padded).get_mut((*blocks).len() - 1) {
                *last_block = pad_block(&*last_block, 16);
            }
        }
        Box::from(padded)
    }

    /// Remove trailing padding, mostly used on decrypted blocks
    fn remove_padding(blocks: &Box<Vec<Vec<u8>>>) -> Box<Vec<Vec<u8>>> {
        let mut removed = *blocks.clone();
        if !Self::validate_block(blocks) {
            panic!("try to remove padding from a non-multiple-block-size input");
        }

        let pad_len = *blocks.last().unwrap().last().unwrap();
        if pad_len == 16 {
            removed.pop();
        } else {
            let last = removed.last_mut().unwrap();
            last.truncate(16 - pad_len as usize);
        }
        Box::from(removed)
    }
}

impl Cipher<&[u8], Box<Vec<Vec<u8>>>, Box<Vec<Vec<u8>>>> for AES_128_CBC {
    fn encrypt(&self, key: &[u8], msg: &Box<Vec<Vec<u8>>>) -> Box<Vec<Vec<u8>>> {
        // Pad and validate msg blocks
        let padded_msg = Self::add_padding(msg);
        if !Self::validate_block(&padded_msg) {
            panic!("Invalid plaintext, not 128-bit block");
        }

        let mut ct: Vec<Vec<u8>> = vec![Vec::new(); padded_msg.len()];
        let mut last = self.iv.clone();
        let mut encrypter =
            SslCrypter::new(SslCipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
        encrypter.pad(false); // disable padding from ECB encryption, only use it as a pure AES Encryption

        // CBC encrypt
        for i in 0..(*padded_msg).len() {
            ct[i] = vec![0; 32]; // avoid assertion
            let mut count = encrypter
                .update(&xor::xor(&last, &(*padded_msg)[i]).unwrap(), &mut ct[i])
                .unwrap();
            count += encrypter.finalize(&mut ct[i][count..]).unwrap();
            ct[i].truncate(count);

            last = ct[i].clone();
        }
        Box::new(ct)
    }

    fn decrypt(&self, key: &[u8], ct: &Box<Vec<Vec<u8>>>) -> Box<Vec<Vec<u8>>> {
        // validate the ciphertext
        if !Self::validate_block(&ct) {
            panic!("Invalid ciphertext, not 128-bit block");
        }

        // CBC decrypt
        let mut pt: Vec<Vec<u8>> = vec![Vec::new(); ct.len()];
        let mut last = &self.iv;
        let mut decrypter =
            SslCrypter::new(SslCipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
        decrypter.pad(false); // disable padding from aes_128_ecb

        for i in 0..(*ct).len() {
            pt[i] = vec![0; 32];
            let mut count = decrypter.update(&ct[i], &mut pt[i]).unwrap();
            count += decrypter.finalize(&mut pt[i][count..]).unwrap();
            pt[i].truncate(count);
            pt[i] = xor::xor(&last, &pt[i]).unwrap();

            last = &ct[i];
        }

        // remove padding
        Self::remove_padding(&Box::from(pt))
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
    use super::super::into_blocks;
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
        let cipher = AES_128_CBC::new();
        let msg_raw = "CBC mode is a block cipher mode that allows us to encrypt
irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks. In CBC
mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.";
        let msg: Box<Vec<Vec<u8>>> = Box::from(into_blocks(msg_raw.as_bytes(), 16));
        let key = "i am pied piper!".as_bytes().to_vec();

        // test encrypt is correctly implemented by comparing to the ciphertext produced by the OpenSSL lib
        assert_eq!(
            openssl::symm::encrypt(
                SslCipher::aes_128_cbc(),
                &key,
                Some(&vec![0; 16]),
                &msg_raw.as_bytes().to_vec()
            )
            .unwrap(),
            cipher
                .encrypt(&key, &msg)
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
        );
        // test correctness of the cipher, i.e. decryption also works
        assert_eq!(cipher.decrypt(&key, &cipher.encrypt(&key, &msg)), msg);
    }
}
