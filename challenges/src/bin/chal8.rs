use encoding::hex;
use std::collections::HashMap;
use std::fs;

fn main() {
    println!("🔓 Challenge 8");
    let ct_hexes = fs::read_to_string("challenges/data/chal8.txt").unwrap();
    let ct_hexes: Vec<_> = ct_hexes
        .lines()
        .map(|line| hex::hexstr_to_bytes(line).unwrap())
        .collect();

    let ct_candidate: Vec<_> = ct_hexes
        .iter()
        .filter(|s| detect_repetition(&s, 16))
        .collect();
    println!(
        "the encrypted hex with ECB is: {:?}",
        hex::bytes_to_hexstr(&ct_candidate[0])
    );
}

fn detect_repetition(content: &[u8], cycle_len: u32) -> bool {
    let mut occurance = HashMap::new();
    for chunk in content.chunks_exact(cycle_len as usize) {
        if occurance.get(chunk) == None {
            occurance.insert(chunk, 1);
        } else {
            return true;
        }
    }
    false
}
