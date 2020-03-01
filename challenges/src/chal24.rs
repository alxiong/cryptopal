use prng::mt19937::{MT19937Rng, RngCore};

pub fn encrypt(seed: u16, msg: &[u8]) -> Vec<u8> {
    let mut rng = MT19937Rng::new(seed as u32);
    let mut key_stream = vec![0 as u8; msg.len()];
    rng.fill_bytes(&mut key_stream);
    xor::xor(&msg, &key_stream).unwrap()
}

pub fn decrypt(seed: u16, ct: &[u8]) -> Vec<u8> {
    let mut rng = MT19937Rng::new(seed as u32);
    let mut key_stream = vec![0 as u8; ct.len()];
    rng.fill_bytes(&mut key_stream);
    xor::xor(&ct, &key_stream).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rng_cipher_correctness() {
        let pt = b"hello, Rustacean!".to_vec();
        let seed = rand::random::<u16>();
        assert_eq!(decrypt(seed, &encrypt(seed, &pt)), pt);
    }
}
