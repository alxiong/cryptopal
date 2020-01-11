use challenges::random_bytes;
use cipher::{self, Mode};
use encoding::base64::Base64;
use std::collections::HashMap;
use std::convert::TryInto;

fn main() {
    println!("🔓 Challenge 14 (should take ~ 16X than chal12)");
    let key = Key::new();
    break_ecb_harder(&key);
}

fn break_ecb_harder(key: &Key) {
    // decipher unknown length
    let unknown_len = decipher_unknown_len(&key);
    assert_eq!(unknown_len, 138); // make sure this is correct for this specific case
    println!("The length of the target bytes: {}", unknown_len);
    println!("Decrypting one byte at a time now ...");

    // break ECB one byte at a time, starting from the last byte
    let mut deciphered: Vec<u8> = Vec::with_capacity(unknown_len);
    for i in 0..unknown_len + 1 {
        let target_suffix_len = 16 - deciphered.len() % 16 - 1;
        let target_prefix_len: u32 = (i as i32 + 1 - unknown_len as i32)
            .rem_euclid(16i32)
            .try_into()
            .unwrap();

        let mut control_group_pt = vec![0 as u8; 2 * 16];
        control_group_pt.extend_from_slice(&random_bytes(target_prefix_len));
        let control_group_ct = target_ct_mod0(&control_group_pt, &key, true);

        let mut focus_block = (control_group_ct.len() / 16) - (i / 16) - 1;
        // NOTE: this next block really kills me to debug. think again please, reader
        if (target_prefix_len + unknown_len as u32) % 16 == 0 {
            focus_block -= 1; // because there will be a dummy block padded
        }

        for byte in u8::min_value()..u8::max_value() {
            let mut pt_experiment: Vec<u8> = vec![];
            if deciphered.len() < 16 {
                pt_experiment.push(byte);
                pt_experiment.extend_from_slice(&deciphered[..]);
                pt_experiment.extend_from_slice(&vec![target_suffix_len as u8; target_suffix_len]);
            } else {
                pt_experiment.push(byte);
                pt_experiment.extend_from_slice(&deciphered[..15]);
            }
            pt_experiment.extend(pt_experiment.clone());
            pt_experiment.extend_from_slice(&random_bytes(target_prefix_len));

            let experiment_group_ct = target_ct_mod0(&pt_experiment, &key, false);
            if experiment_group_ct[..16]
                == control_group_ct[focus_block * 16..(focus_block + 1) * 16]
            {
                deciphered.insert(0, byte);
                break;
            }
        }
        println!(
            "progress: {} bytes decrypted: {:?}",
            deciphered.len(),
            String::from_utf8(deciphered.clone()).unwrap()
        );
    }

    println!("Decrypted: \n{:?}", String::from_utf8(deciphered).unwrap());
}

pub struct Key(Vec<u8>);

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
        // NOTE: the next line is the difference between chal14 and chal12
        // i.e. a random-length prefix
        actual_input.extend_from_slice(&random_bytes(rand::random::<u8>() as u32)[..]);
        actual_input.extend_from_slice(&input);
        actual_input.extend_from_slice(&unknown_base64.as_bytes()[..]);

        let ecb_cipher = cipher::new(Mode::ECB, None);
        ecb_cipher.encrypt(&self.0, &actual_input)
    }
}

fn decipher_unknown_len(key: &Key) -> usize {
    // feed 3 same controlled blocks, the first could be used to pad the random prefix to exact multiple
    // then there should be at least 2 same block in the ciphertext.
    // (prefix.len + controlled.len) mod 16 is 0~15, each has an equal probability of 1/16
    // by repeatedly calling encryption oracle, and identifying the ciphertext of the prefixed_unknown:
    // [blah, blah, blah, same, same, prefixed_unknown]
    // the two "same" block is due to the controlled msg we pass in, and the prefix for the target could be
    // any of 0~15, and by collecting all possible ciphertext, we could deduce the length
    let mut occurance: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut max_unknown_len = 0;
    while occurance.len() < 16 {
        let prefixed_unknown_ct_candidate: Vec<u8> =
            get_post_signal_ct(&key.encryption_oracle(&vec![0 as u8; 3 * 16 - 1])).unwrap();
        let ct_candidate_len = prefixed_unknown_ct_candidate.len();
        if ct_candidate_len > max_unknown_len {
            max_unknown_len = ct_candidate_len;
        }
        occurance.insert(prefixed_unknown_ct_candidate, ct_candidate_len);
    }

    // find how many among the 16 candidates have a 16 byte longer blocks
    // and the actual_len = max_len - (16 - # of 1 block longer candidates)
    let mut longer_block_count = 0;
    for val in occurance.values() {
        if *val == max_unknown_len {
            longer_block_count += 1;
        }
    }
    max_unknown_len - (16 - longer_block_count) - 16
}

// two equal blocks in the ciphertext input is called the "signal blocks", and the remaining
// blocks are post-signal portion, which is the output of this function
fn get_post_signal_ct(ct: &[u8]) -> Option<Vec<u8>> {
    // NOTE: precondition check skipped on whether `ct` is an exact_multiple, for simplicity
    let ct_2d = cipher::into_blocks(&ct, 16);
    let result = ct_2d
        .iter()
        .fold((vec![], false), |mut acc: (Vec<Vec<u8>>, bool), x| {
            if !acc.1 {
                if !acc.0.is_empty() && acc.0[0] == *x {
                    acc.0.clear();
                    acc.1 = true;
                } else {
                    acc.0.clear();
                    acc.0.push(x.clone());
                }
            } else {
                acc.0.push(x.clone());
            }
            acc
        });

    match result.1 {
        true => Some(result.0.into_iter().flatten().collect::<Vec<u8>>()),
        false => None,
    }
}

fn get_signal_ct(ct: &[u8]) -> Option<Vec<u8>> {
    let ct_2d = cipher::into_blocks(&ct, 16);
    for i in 0..ct_2d.len() - 1 {
        if ct_2d[i] == ct_2d[i + 1] {
            return Some(ct_2d[i].clone());
        }
    }
    None
}

// Apologize that I couldn't come up with a better name, this sounds confusing as hell.
// This function returns the post-signal ciphertext only when the plaintext has a 0(mod 16)
// length prefix, which means the controlled input starts on fresh block, which gives us
// control over how many bytes are we pushing the unknown portion(given that we already knew
// its length)
fn target_ct_mod0(pt: &[u8], key: &Key, controlled: bool) -> Vec<u8> {
    // On average, this loop will repeat 16 times before getting a desirable ciphertext
    // because the random-length prefix, the probability of a fresh block start for controlled
    // input in the middle is 1/16
    loop {
        let ct: Vec<u8> = key.encryption_oracle(pt);
        if controlled {
            let result = get_post_signal_ct(&ct);
            if result.is_some() {
                return result.unwrap();
            }
        } else {
            let result = get_signal_ct(&ct);
            if result.is_some() {
                return result.unwrap();
            }
        }
    }
}
