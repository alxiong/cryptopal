use challenges::random_bytes;
use cipher::{self, Mode};
use encoding::base64::Base64;

fn main() {
    println!("🔓 Challenge 12 (this may take a while ...)");
    let key = Key::new();
    break_ecb(&key);
}

// Byte-at-a-time ECB decryption
fn break_ecb(key: &Key) {
    // decipher unknown length
    let unknown_len = decipher_unknown_len(&key).unwrap();

    // make sure it's ECB encrypted
    assert!(detect_ecb(&key));

    // break encryption one byte at a time
    let mut deciphered: Vec<u8> = vec![];
    for i in 0..unknown_len {
        // breaking the i-th byte of the unknown bytes
        let prefix_len = 16 - deciphered.len() % 16 - 1;

        // first get a prefixed ciphertext as a control group/reference
        let ct_controlled = key.encryption_oracle(&vec![0 as u8; prefix_len]);
        // then try different experiment group inputs and see which one matches the reference
        for byte in u8::min_value()..u8::max_value() {
            let mut pt_experiment: Vec<u8> = vec![];
            if deciphered.len() < 16 {
                // for the first 16 unknown bytes, we need the prefix to build experiment group input
                pt_experiment.extend_from_slice(&vec![0 as u8; 16 - deciphered.len() - 1]);
                pt_experiment.extend_from_slice(&deciphered[..]);
                pt_experiment.extend_from_slice(&vec![byte]);
            } else {
                // for the 16-th unknown byte onwards, we construct the experiment group input from part of
                // the deciphered bytes
                pt_experiment.extend_from_slice(&deciphered[i - 15..i]);
                pt_experiment.extend_from_slice(&vec![byte]);
            }

            let ct_experiment = key.encryption_oracle(&pt_experiment);
            let focus_block = i / 16;
            if ct_experiment[..16] == ct_controlled[focus_block * 16..(focus_block + 1) * 16] {
                // if the experiment ciphertext of the focused block matches that of the reference group
                // then we successfully deciphered the i-th byte in unknown
                deciphered.push(byte);
            }
        }
    }

    println!("Decrypted: \n{:?}", String::from_utf8(deciphered).unwrap());
}

struct Key(Vec<u8>); // consistent by private field

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

        let ecb_cipher = cipher::new(Mode::ECB);
        ecb_cipher.encrypt(&self.0, &actual_input)
    }
}

fn detect_ecb(key: &Key) -> bool {
    let crafted_msg = vec![0 as u8; 32];
    let ct = key.encryption_oracle(&crafted_msg);
    if ct.as_slice()[0..16] == ct.as_slice()[16..32] {
        return true;
    }
    false
}

fn decipher_unknown_len(key: &Key) -> Option<usize> {
    let max_unknown_len = key.encryption_oracle(&vec![]).len();
    for padding_len in 1..16 {
        if key.encryption_oracle(&vec![0 as u8; padding_len]).len() == max_unknown_len + 16 {
            return Some(max_unknown_len - padding_len);
        }
    }
    None
}
