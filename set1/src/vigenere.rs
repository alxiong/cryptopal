use std::collections::HashMap;
use std::str;

// Hamming distance is the number of different bits
pub fn hamming_distance(s1: &str, s2: &str) -> u32 {
    let s1 = s1.as_bytes().to_vec();
    let s2 = s2.as_bytes().to_vec();
    s1.iter()
        .zip(s2.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum()
}

pub fn key_size(ciphertext: &str) -> u32 {
    // assuming KEYSIZE >= 4 from most Kasiski test
    let mut average_distance: HashMap<_, f32> = HashMap::new();
    // TODO: only testing key size ranging from [4,40]
    // need precondition check to make sure ciphertext length is safe
    for key_len in 4..41 {
        let mut total_distance: f32 = 0.0;
        let mut total_pair = 0;
        for chunk in ciphertext.as_bytes().chunks_exact(4 * key_len) {
            total_distance += hamming_distance(
                str::from_utf8(&chunk[..key_len]).unwrap(),
                str::from_utf8(&chunk[key_len..key_len * 2]).unwrap(),
            ) as f32
                / key_len as f32;
            total_distance += hamming_distance(
                str::from_utf8(&chunk[..key_len]).unwrap(),
                str::from_utf8(&chunk[key_len * 2..key_len * 3]).unwrap(),
            ) as f32
                / key_len as f32;
            total_distance += hamming_distance(
                str::from_utf8(&chunk[..key_len]).unwrap(),
                str::from_utf8(&chunk[key_len * 3..key_len * 4]).unwrap(),
            ) as f32
                / key_len as f32;

            total_pair += 3;
        }
        average_distance.insert(key_len, total_distance as f32 / total_pair as f32);
    }
    let mut candidates: Vec<(_, f32)> = average_distance.into_iter().collect();
    candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    candidates[0].0 as u32
}

// drop the remainder, thus lossy
pub fn into_block_lossy(s: &str, size: u32) -> Vec<String> {
    let mut block: Vec<String> = vec![];
    let chars: Vec<_> = s.chars().collect();

    for chunk in chars.chunks_exact(size as usize) {
        block.push(chunk.iter().collect());
    }
    block
}

// TODO: add precondition contract to check all_equal_length for the input
pub fn transpose_block(block: Vec<String>) -> Vec<String> {
    let char_matrix: Vec<Vec<char>> = block
        .as_slice()
        .iter()
        .map(|s| s.chars().collect())
        .collect();

    let mut trans_block: Vec<String> = vec![String::new(); char_matrix[0].len()];
    for chars in char_matrix.iter() {
        for (index, c) in chars.iter().enumerate() {
            trans_block[index].push_str(&c.to_string());
        }
    }
    trans_block
}

#[cfg(test)]
mod vigenere_tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance("this is a test", "wokka wokka!!!"), 37);
    }
    #[test]
    fn test_into_block_lossy() {
        assert_eq!(
            into_block_lossy("abcdefghijklmnopqrstuvwxyz12345678", 6),
            vec!["abcdef", "ghijkl", "mnopqr", "stuvwx", "yz1234"]
        );
    }
    #[test]
    fn test_transpose_block() {
        let block = vec![
            String::from("jack"),
            String::from("alex"),
            String::from("eric"),
        ];
        assert_eq!(transpose_block(block), vec!["jae", "alr", "cei", "kxc"]);
    }
}
