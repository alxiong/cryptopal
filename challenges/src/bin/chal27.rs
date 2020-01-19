use challenges::random_bytes;
use cipher::{cbc::AES_128_CBC, Cipher};
use std::convert::TryInto;
use xor;

fn main() {
    println!("🔓 Challenge 27");
    let key = Key::new();
    key_recovery_attack(&key);
}

fn key_recovery_attack(key: &Key) {
    let pt_0 = "yellow submarine".as_bytes().to_vec();
    let pt_1_2 = "1234567890abcdef1234567890abcdef".as_bytes().to_vec();

    let ct = key.encryption_oracle(&[pt_0.clone(), pt_1_2].concat());
    let mut tampered_ct = vec![];
    tampered_ct.extend_from_slice(&ct[..16]); // prefixed iv
    tampered_ct.extend_from_slice(&ct[16..32]); // C1
    tampered_ct.extend_from_slice(&[0 as u8; 16]); // 0
    tampered_ct.extend_from_slice(&ct[16..32]); // C1
    tampered_ct.extend_from_slice(&ct[48..]); // second last and padding block

    if let Err(decrypted_pt) = key.decryption_oracle(&tampered_ct) {
        let iv = xor::xor(&pt_0, &decrypted_pt[32..48]).unwrap();
        println!("Ah! The key is recovered: {:?}", iv);
    }
}

struct Key(Vec<u8>);

impl Key {
    pub fn new() -> Key {
        let key = random_bytes(16);
        println!("Whisper: key is {:?}", key);
        Key(key)
    }

    pub fn encryption_oracle(&self, input: &[u8]) -> Vec<u8> {
        // quote out specical character ('=' and ';') in the input
        // by replace them with "%3d" and "%3b" respectively
        let mut cleaned_input: Vec<u8> = vec![];
        for byte in input.iter() {
            match byte {
                b';' => cleaned_input.extend_from_slice(b"%3b"),
                b'=' => cleaned_input.extend_from_slice(b"%3d"),
                _ => cleaned_input.push(*byte),
            };
        }

        // NOTE: this is where we feed key into CBC as its iv
        let cbc_cipher = AES_128_CBC::from_iv(self.0.as_slice().try_into().unwrap());

        cbc_cipher.encrypt(&self.0, &cleaned_input)
    }

    // returns true (which pass the admin=true test) or Error with invalid plaintext `Vec<u8>`
    pub fn decryption_oracle(&self, ct: &[u8]) -> Result<bool, Vec<u8>> {
        let cbc_cipher = AES_128_CBC::from_iv(self.0.as_slice().try_into().unwrap());
        let pt = cbc_cipher.decrypt(&self.0, ct);
        if String::from_utf8(pt.clone()).is_err() {
            return Err(pt);
        }
        Ok(pt
            .windows(11)
            .position(|x| x == ";admin=true".as_bytes())
            .is_some())
    }
}
