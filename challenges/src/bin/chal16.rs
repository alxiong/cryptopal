use challenges::random_bytes;
use cipher::{self, Mode};
use xor;

fn main() {
    println!("🔓 Challenge 16");
    let key = Key::new();
    bitflipping_attack(&key);
}

// c[2] XOR D(k, c[3]) = m[3], and c[2] and m[3] are known
// by finding out the XOR diff between m[3] and m'[3] (which contains ";admin=true")
// we can deduce the c'[2] desired
// p.s. Do remember that ciphertext is prepended with iv
fn bitflipping_attack(key: &Key) {
    let input = random_bytes(2 + 16 * 2); // 2 is because the (prefix + 2) mod 16 = 0
    let mut ct = key.encryption_oracle(&input);
    let xor_diff = xor::xor(&input[18..], &";admin=true;rand".as_bytes()).unwrap();
    let third_ciphertext_block = xor::xor(&ct[48..64], &xor_diff).unwrap();
    ct.splice(48..64, third_ciphertext_block.iter().cloned());

    assert!(key.decryption_oracle(&ct));
    println!("😏 Successfully fool the system to be an admin");
}

struct Key(Vec<u8>);

impl Key {
    pub fn new() -> Key {
        Key(random_bytes(16))
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

        let mut actual_pt: Vec<u8> = vec![];
        actual_pt.extend_from_slice(&"comment1=cooking\x20MCs;userdata=".as_bytes());
        actual_pt.extend_from_slice(&cleaned_input);
        actual_pt.extend_from_slice(&";comment2=\x20like\x20a\x20pound\x20of\x20bacon".as_bytes());

        let cbc_cipher = cipher::new(Mode::CBC);

        cbc_cipher.encrypt(&self.0, &actual_pt)
    }

    pub fn decryption_oracle(&self, ct: &[u8]) -> bool {
        let cbc_cipher = cipher::new(Mode::CBC);
        let pt = cbc_cipher.decrypt(&self.0, ct);
        pt.windows(11)
            .position(|x| x == ";admin=true".as_bytes())
            .is_some()
    }
}
