#![deny(clippy::all)]
pub mod freq_analysis;
pub mod vigenere;

// TODO: add precondition contract to check all_equal_length for the input
// TODO: improve to more effeicient in-place transposition
pub fn transpose_block(block: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut transposed: Vec<Vec<u8>> = vec![];
    for row in block.iter() {
        for (index, &byte) in row.iter().enumerate() {
            match transposed.get_mut(index) {
                Some(v) => v.push(byte),
                None => transposed.insert(index, vec![byte]),
            };
        }
    }
    transposed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_transpose_block() {
        assert_eq!(
            transpose_block(&[b"jack".to_vec(), b"alex".to_vec(), b"eric".to_vec(),]),
            vec![b"jae", b"alr", b"cei", b"kxc"]
        );
    }
}
