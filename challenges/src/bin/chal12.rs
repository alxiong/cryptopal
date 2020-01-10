use challenges::chal12::{decipher_unknown_len, detect_ecb, Key};

// NOTE: the rationale of putting all those chal12 related struct and function to its module is for reuse in chal14
// minimize code repetition
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
