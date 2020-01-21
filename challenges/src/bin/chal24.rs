use challenges::chal24;
use prng::mt19937::{MT19937Rng, RngCore};
use std::time::SystemTime;
use xor;

fn main() {
    println!("🔓 Challenge 24");
    recover_key();
    if check_reset_token(&gen_reset_token()) && !check_reset_token(&gen_invalid_reset_token()) {
        println!("Passed reset token validation");
    }
}

fn recover_key() {
    let key = rand::random::<u16>();
    println!("🤫 Whisper: the key is {:?}", key);

    // prepare plaintext with randomized prefix and encrypt it
    let pt = prepare_plaintext();
    let ct = chal24::encrypt(key, &pt);

    let partial_key_stream = xor::xor(&b"AAAAAAAAAAAAAA"[..], &ct[ct.len() - 14..]).unwrap();
    for i in 0..(u16::max_value() as usize) + 1 {
        let mut mt_candidate = MT19937Rng::new(i as u32);
        let mut key_stream = vec![0 as u8; ct.len()];
        mt_candidate.fill_bytes(&mut key_stream);
        if key_stream.ends_with(&partial_key_stream) {
            println!("💡 Found key: {:?}", i);
            return;
        }
    }
}

fn prepare_plaintext() -> Vec<u8> {
    let mut pt = vec![rand::random::<u8>(); rand::random::<u8>() as usize];
    pt.extend_from_slice(&b"AAAAAAAAAAAAAA"[..]);
    pt
}

fn gen_reset_token() -> Vec<u8> {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u16;
    let pt = prepare_plaintext();
    chal24::encrypt(seed, &pt)
}

fn gen_invalid_reset_token() -> Vec<u8> {
    chal24::encrypt(rand::random::<u16>(), &prepare_plaintext())
}

fn check_reset_token(token: &[u8]) -> bool {
    // assumption: it hasn't elasped 1 min (60 sec) since the token generation
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u16;

    let partial_key_stream = xor::xor(&b"AAAAAAAAAAAAAA"[..], &token[token.len() - 14..]).unwrap();
    for i in now - 60..now + 1 {
        let mut mt_candidate = MT19937Rng::new(i as u32);
        let mut key_stream = vec![0 as u8; token.len()];
        mt_candidate.fill_bytes(&mut key_stream);
        if key_stream.ends_with(&partial_key_stream) {
            return true;
        }
    }
    false
}
