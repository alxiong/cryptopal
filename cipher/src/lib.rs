pub mod cbc;

use std::ops::Deref;

pub trait Cipher<K, M, C>
where
    M: Deref,
    C: Deref,
{
    fn encrypt(&self, key: K, msg: &M) -> C;
    fn decrypt(&self, key: K, ct: &C) -> M;
}

pub fn into_blocks(s: &[u8], size: usize) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = vec![];
    for chunk in s.chunks(size) {
        blocks.push(chunk.to_vec());
    }
    blocks
}

pub fn from_blocks(blocks: Vec<Vec<u8>>) -> String {
    String::from_utf8(blocks.into_iter().flatten().collect::<Vec<_>>()).unwrap()
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
            from_blocks(vec![
                "hel".as_bytes().to_vec(),
                "low".as_bytes().to_vec(),
                "orl".as_bytes().to_vec(),
                "d".as_bytes().to_vec()
            ]),
            "helloworld"
        );
    }
}
