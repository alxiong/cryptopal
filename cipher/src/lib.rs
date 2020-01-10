pub mod cbc;
pub mod ecb;
pub mod padding;

#[derive(Debug)]
pub enum Mode {
    ECB,
    CBC,
}

/// Represents a cipher
pub trait Cipher {
    fn encrypt(&self, key: &[u8], msg: &[u8]) -> Vec<u8>;
    fn decrypt(&self, key: &[u8], ct: &[u8]) -> Vec<u8>;
}

/// Instantiate a new cipher provided a specific mode and optional initialization vector
pub fn new(mode: Mode, iv: Option<&[u8; 16]>) -> Box<dyn Cipher> {
    match mode {
        Mode::CBC => Box::from(cbc::AES_128_CBC::new(iv.unwrap())),
        Mode::ECB => Box::from(ecb::AES_128_ECB::new()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_blocks() {
        assert_eq!(
            into_blocks("helloworld".as_bytes(), 3),
            vec![
                "hel".as_bytes().to_vec(),
                "low".as_bytes().to_vec(),
                "orl".as_bytes().to_vec(),
                "d".as_bytes().to_vec()
            ]
        );
    }

    #[test]
    fn test_from_blocks() {
        assert_eq!(
            from_blocks(&vec![
                "hel".as_bytes().to_vec(),
                "low".as_bytes().to_vec(),
                "orl".as_bytes().to_vec(),
                "d".as_bytes().to_vec()
            ]),
            "helloworld".as_bytes().to_vec()
        );
    }
}
