use challenges::random_bytes;
use cipher::Mode;
use rand::{self, Rng};

fn main() {
    println!("🔓 Challenge 11");
    println!(
        "Ahha! Let me guess, it's {:?}, right? 😉",
        detect_ecb_or_cbc()
    );
}

// break semantic security of ECB
fn detect_ecb_or_cbc() -> Mode {
    // Explaination: ECB mode is not semantically secure. Particularly, given a message with two identical 128-bit
    // blocks, the respective ciphertext block should also be the same. Namely, if m[i] = m[j], then c[i] = c[j]
    //
    // This vulnerability gives us leverage by crafting our message to make sure the second and third block of the
    // plaintext to be encrypted are the same. (since it will be prepended by 5~10 byte, we need some buffer to fill in
    // the first block, and we have no control over what the first block will be with the random prefix)
    let crafted_msg = vec![0 as u8; 32 + (16 - 5)];
    let ct = encryption_oracle(&crafted_msg);
    if ct.as_slice()[16..32] == ct.as_slice()[32..48] {
        Mode::ECB
    } else {
        Mode::CBC
    }
}

fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    // prefix and suffix the input with random bytes (5~10 in length)
    let mut padded_input: Vec<u8> = vec![];
    let prefix = random_bytes(rng.gen_range(5, 11));
    let suffix = random_bytes(rng.gen_range(5, 11));
    padded_input.extend_from_slice(&prefix[..]);
    padded_input.extend_from_slice(&input[..]);
    padded_input.extend_from_slice(&suffix[..]);

    // encrypt the padded_input with one of ECB and CBC, chosen at random
    if rand::random::<bool>() {
        let ecb_cipher = cipher::new(Mode::ECB, None);
        let ct = ecb_cipher.encrypt(&random_bytes(16)[..], &padded_input);
        println!("Using ECB, shhh 🤫");
        ct
    } else {
        let cbc_cipher = cipher::new(Mode::CBC, Some(&[random_bytes(1)[0]; 16]));
        let ct = cbc_cipher.encrypt(&random_bytes(16)[..], &padded_input);
        println!("Using CBC, shhh 🤫");
        ct
    }
}
