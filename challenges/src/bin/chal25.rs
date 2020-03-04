use challenges::random_bytes_array;
use cipher::{ctr::AES_128_CTR, Cipher};
use std::fs;

fn main() {
    println!("🔓 Challenge 25");
    let ctr_cipher = AES_128_CTR::new_with_nonce(0);
    let pt = fs::read_to_string("challenges/data/chal25.txt")
        .unwrap()
        .as_bytes()
        .to_vec();
    let mut key = vec![0 as u8; 16];
    random_bytes_array(&mut key);
    let ct = ctr_cipher.encrypt(&key, &pt);

    let decrypted = break_ctr(&ct, &key);
    assert_eq!(decrypted, pt);
    println!("Successfully decrypted");
}

fn break_ctr(ct: &[u8], key: &[u8]) -> Vec<u8> {
    let craft_pt = vec![0 as u8; ct.len()];
    let key_stream = xor::xor(&craft_pt, &edit(&ct, &key, 0, &craft_pt)).unwrap();
    xor::xor(&key_stream, &ct).unwrap()
}

// chosen plaintext with fixed nounce
fn edit(ct: &[u8], key: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
    let ctr_cipher = AES_128_CTR::new_with_nonce(0);
    let mut new_pt = ctr_cipher.decrypt(&key, &ct);
    new_pt.splice(offset.., newtext.iter().cloned());
    ctr_cipher.encrypt(&key, &new_pt)
}
