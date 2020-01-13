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

/// Instantiate a new cipher provided a specific mode and optional initialization vector
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
pub fn from_blocks(blocks: &Vec<Vec<u8>>) -> Vec<u8> {
    blocks.clone().into_iter().flatten().collect::<Vec<_>>()
}

pub fn random_bytes_array(arr: &mut [u8]) {
    for i in 0..arr.len() {
        arr[i] = rand::random::<u8>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_blocks() {
        assert_eq!(
            into_blocks("helloworld".as_bytes(), 3),
            vec![
                "hel".as_bytes(),
                "low".as_bytes(),
                "orl".as_bytes(),
                "d".as_bytes()
            ]
        );
    }

    #[test]
    fn test_from_blocks() {
        assert_eq!(
            from_blocks(&vec![
                b"hel".to_vec(),
                b"low".to_vec(),
                b"orl".to_vec(),
                b"d".to_vec(),
            ]),
            "helloworld".as_bytes()
        );
    }
}
