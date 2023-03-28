use challenges::random_bytes;
use cipher::{self, cbc::AES_128_CBC, padding, Cipher};
use rand::{self, Rng};
use std::fs;

fn main() {
    println!("🔓 Challenge 17");
    let key = Key::new();
    padding_oracle_attack(&key);
}

fn padding_oracle_attack(key: &Key) {
    let ct = key.encryption_oracle(); // remember the first 16-byte is iv

    let mut found = false;
    let mut random_block = vec![];
    // Explain: assuming the ciphertext is only 3 block long, if we tamper the second block c[1] and XOR
    // with a random block B, then the decrypted 3rd block, m'[2] = m[2] ^ B.
    // If m'[2] is a valid padded block, then the likihood suggests the last byte is 1, thus, we can
    // reverse engineer the orignial last byte of m[2], which also is the padding length value
    while !found {
        let mut ct_tampered = ct.clone();
        random_block = random_bytes(16);
        ct_tampered.splice(
            ct.len() - 32..ct.len() - 16,
            xor::xor(&random_block, &ct[ct.len() - 32..ct.len() - 16])
                .unwrap()
                .iter()
                .cloned(),
        );
        found = key.padding_oracle(&ct_tampered);
    }

    let last_byte = random_block.last().unwrap() ^ b'\x01';
    println!("Padding length is {}", last_byte);
    // NOTE: up until here, based on the `last_byte`, we could already narrow down the plaintext based
    // on their length mod 16, and even probably deduce which one out of the ten string is
    // encrypted, but here, we will go further and directly decrypt the entire plaintext using
    // padding_oracle, as if we know nothing about the plaintext
    let mut pt = vec![last_byte; last_byte as usize];

    while pt.len() < ct.len() - 16 {
        let pt_len = pt.len();
        let mut random_block: Vec<u8> = vec![0 as u8; 16 - pt_len % 16];
        random_block.extend_from_slice(
            &xor::xor(&vec![(pt_len % 16 + 1) as u8; pt_len % 16], &pt[..pt_len % 16])
                .unwrap()
                .as_slice(),
        );

        let mut found = false;
        while !found {
            let mut ct_tampered = ct.clone();
            ct_tampered.truncate(ct.len() - 16 * (pt_len / 16));
            let ct_tampered_len = ct_tampered.len();

            random_block.splice(
                ..16 - pt_len % 16,
                random_bytes((16 - pt_len % 16) as u32).iter().cloned(),
            );
            ct_tampered.splice(
                ct_tampered_len - 32..ct_tampered_len - 16,
                xor::xor(
                    &random_block,
                    &ct_tampered.clone()[ct_tampered_len - 32..ct_tampered_len - 16],
                )
                .unwrap()
                .iter()
                .cloned(),
            );

            found = key.padding_oracle(&ct_tampered);
        }
        pt.insert(0, random_block.get(15 - pt_len % 16).unwrap() ^ (pt_len % 16 + 1) as u8);
    }
    println!("decrypted: {:?}", String::from_utf8(pt).unwrap());
}

struct Key(Vec<u8>);

impl Key {
    pub fn new() -> Key {
        Key(random_bytes(16))
    }

    pub fn encryption_oracle(&self) -> Vec<u8> {
        let pt_str = fs::read_to_string("challenges/data/chal17.txt").unwrap();
        let pt_candidates: Vec<_> = pt_str.lines().collect();

        let mut rng = rand::thread_rng();
        let pt = pt_candidates[rng.gen_range(0..pt_candidates.len())];

        let cbc_cipher = AES_128_CBC::new();
        cbc_cipher.encrypt(&self.0, &pt.as_bytes())
    }

    pub fn padding_oracle(&self, ct: &[u8]) -> bool {
        let pt_with_padding = AES_128_CBC::decrypt_with_padding(&self.0, &ct);
        padding::validate_padding(&pt_with_padding, 16)
    }
}
