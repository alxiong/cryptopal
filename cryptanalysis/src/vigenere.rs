use super::{freq_analysis, transpose_block};
use std::collections::HashMap;

pub fn extract_key(ct: &[u8]) -> Vec<u8> {
    let mut key: Vec<u8> = vec![];
    let key_size = guess_key_size(&ct);
    let block = transpose_block(&into_block_lossy(&ct, key_size));

    // for each row in the block is a XORed ciphertext
    for row in block.iter() {
        let ct = freq_analysis::break_single_byte_xor(&row);
        key.push(row[0] ^ ct.as_bytes()[0]);
    }
    println!("key: {:?}", key);
    key
}

// NOTE: justification for accepting `&[u8]` instead of `&sr` :
// these are internal/private function, and most operations are on raw bytes
// thus only externally exposed function has input parameters of &str, whereas
// private functions uses [u8] to avoid excessive type conversion.

// Hamming distance is the number of different bits
fn hamming_distance(s1: &[u8], s2: &[u8]) -> u32 {
    s1.iter()
        .zip(s2.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum()
}

fn guess_key_size(ct: &[u8]) -> u32 {
    let mut average_distance: HashMap<_, f32> = HashMap::new();
    // NOTE: only testing key size ranging from [2,40]
    // need precondition check to make sure ciphertext length is safe
    for key_len in 2..41 {
        let mut total_distance: f32 = 0.0;
        let mut total_pair = 0;
        for chunk in ct.chunks_exact(4 * key_len) {
            for i in 1..4 {
                total_distance +=
                    hamming_distance(&chunk[..key_len], &chunk[key_len * i..key_len * (i + 1)])
                        as f32
                        / key_len as f32;
            }
            total_pair += 3;
        }
        average_distance.insert(key_len, total_distance as f32 / total_pair as f32);
    }

    // select the one with the least hamming distance
    let mut candidates: Vec<(_, f32)> = average_distance.into_iter().collect();
    candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    candidates[0].0 as u32
}

// drop the remainder (doesn't affect key extraction), thus lossy
fn into_block_lossy(s: &[u8], size: u32) -> Vec<Vec<u8>> {
    let mut block: Vec<Vec<u8>> = vec![];
    for chunk in s.chunks_exact(size as usize) {
        block.push(chunk.to_vec());
    }
    block
}

#[cfg(test)]
mod vigenere_tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        assert_eq!(
            hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
            37
        );
    }

    #[test]
    fn test_into_block_lossy() {
        assert_eq!(
            into_block_lossy(b"abcdefghijklmnopqrstuvwxyz12345678", 6),
            vec![b"abcdef", b"ghijkl", b"mnopqr", b"stuvwx", b"yz1234"]
        );
    }
}
