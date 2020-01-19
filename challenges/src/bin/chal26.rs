use challenges::random_bytes;
use cipher::{ctr::AES_128_CTR, Cipher};

fn main() {
    println!("🔓 Challenge 26");
    let key = Key::new();
    bitflipping_attack(&key);
}

fn bitflipping_attack(key: &Key) {
    let input = random_bytes(2 + 16);
    let mut ct = key.encryption_oracle(&input);
    let xor_diff = xor::xor(&input[2..], &";admin=true;rand".as_bytes()).unwrap();
    let third_ct_block = xor::xor(&ct[32..48], &xor_diff).unwrap();
    ct.splice(32..48, third_ct_block.iter().cloned());

    assert!(key.decryption_oracle(&ct));
    println!("😏 Successfully fool the system to be an admin");
}

struct Key(Vec<u8>);

impl Key {
    pub fn new() -> Key {
        Key(random_bytes(16))
    }

    pub fn encryption_oracle(&self, input: &[u8]) -> Vec<u8> {
        let mut cleaned_input: Vec<u8> = vec![];
        for byte in input.iter() {
            match byte {
                b';' => cleaned_input.extend_from_slice(b"%3b"),
                b'=' => cleaned_input.extend_from_slice(b"%3d"),
                _ => cleaned_input.push(*byte),
            };
        }

        let mut actual_pt: Vec<u8> = vec![];
        actual_pt.extend_from_slice(&"comment1=cooking\x20MCs;userdata=".as_bytes());
        actual_pt.extend_from_slice(&cleaned_input);
        actual_pt.extend_from_slice(&";comment2=\x20like\x20a\x20pound\x20of\x20bacon".as_bytes());

        let ctr_cipher = AES_128_CTR::new_with_nonce(0);
        ctr_cipher.encrypt(&self.0, &actual_pt)
    }

    pub fn decryption_oracle(&self, ct: &[u8]) -> bool {
        let ctr_cipher = AES_128_CTR::new_with_nonce(0);
        let pt = ctr_cipher.decrypt(&self.0, &ct);
        pt.windows(11)
            .position(|x| x == ";admin=true".as_bytes())
            .is_some()
    }
}
