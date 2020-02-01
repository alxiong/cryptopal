#![deny(clippy::all)]
pub mod cbc;
pub mod ctr;
pub mod ecb;
pub mod padding;

use rand;

#[derive(Debug)]
pub enum Mode {
    ECB,
    CBC,
    CTR,
}

/// Represents a cipher
pub trait Cipher {
    fn encrypt(&self, key: &[u8], msg: &[u8]) -> Vec<u8>;
    fn decrypt(&self, key: &[u8], ct: &[u8]) -> Vec<u8>;
}

/// Instantiate a new cipher provided a specific mode and default initialization vector/nonce
pub fn new(mode: Mode) -> Box<dyn Cipher> {
    match mode {
        Mode::CBC => Box::from(cbc::AES_128_CBC::new()),
        Mode::ECB => Box::from(ecb::AES_128_ECB::new()),
        Mode::CTR => Box::from(ctr::AES_128_CTR::new()),
    }
}

/// Transforms a slice of bytes to a 2D vector (blocks) given the block size
pub fn into_blocks(s: &[u8], size: usize) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = vec![];
    for chunk in s.chunks(size) {
        blocks.push(chunk.to_vec());
    }
    blocks
}

/// Inverse transformation of `into_blocks`
pub fn from_blocks(blocks: &[Vec<u8>]) -> Vec<u8> {
    blocks.to_vec().into_iter().flatten().collect::<Vec<u8>>()
}

pub fn random_bytes_array(arr: &mut [u8]) {
    for item in arr.iter_mut() {
        *item = rand::random::<u8>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_blocks() {
        assert_eq!(
            into_blocks(b"helloworld", 3),
            vec![
                b"hel".to_vec(),
                b"low".to_vec(),
                b"orl".to_vec(),
                b"d".to_vec()
            ]
        );
    }

    #[test]
    fn test_from_blocks() {
        assert_eq!(
            from_blocks(&[
                b"hel".to_vec(),
                b"low".to_vec(),
                b"orl".to_vec(),
                b"d".to_vec(),
            ]),
            b"helloworld"
        );
    }
}
