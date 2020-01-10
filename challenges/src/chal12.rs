use super::random_bytes;
use cipher::{self, Mode};
use encoding::base64::Base64;

pub struct Key(Vec<u8>); // consistent by private field

impl Key {
    pub fn new() -> Key {
        Key(random_bytes(16))
    }

    pub fn encryption_oracle(&self, input: &[u8]) -> Vec<u8> {
        let unknown_base64 = Base64::from_str(
            &"
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"
                .lines()
                .collect::<String>(),
        )
        .unwrap();
        let mut actual_input = vec![];
        actual_input.extend_from_slice(&input);
        actual_input.extend_from_slice(&unknown_base64.as_bytes()[..]);

        let ecb_cipher = cipher::new(Mode::ECB, None);
        ecb_cipher.encrypt(&self.0, &actual_input)
    }
}

pub fn detect_ecb(key: &Key) -> bool {
    let crafted_msg = vec![0 as u8; 32];
    let ct = key.encryption_oracle(&crafted_msg);
    if ct.as_slice()[0..16] == ct.as_slice()[16..32] {
        return true;
    }
    false
}

pub fn decipher_unknown_len(key: &Key) -> Option<usize> {
    let max_unknown_len = key.encryption_oracle(&vec![]).len();
    for padding_len in 1..16 {
        if key.encryption_oracle(&vec![0 as u8; padding_len]).len() == max_unknown_len + 16 {
            return Some(max_unknown_len - padding_len);
        }
    }
    None
}
