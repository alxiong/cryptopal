use std::thread;
use std::time::Duration;

pub fn insecure_compare(b1: &[u8], b2: &[u8]) -> bool {
    if b1.len() != b2.len() {
        return false;
    }
    for (i, _) in b1.iter().enumerate() {
        if b1[i] != b2[i] {
            return false;
        }
        if !cfg!(test) {
            // will not run during test to speed up cargo test
            thread::sleep(Duration::from_millis(50));
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    #[test]
    fn sha1_hmac_correctness() {
        let msg = b"The quick brown fox jumps over the lazy dog".to_vec();
        let key = b"whatever secret".to_vec();
        let mut sha1_hmac = Hmac::<Sha1>::new_varkey(&key).expect("HMAC can take key of any size");
        sha1_hmac.input(&msg);
        let result_code = sha1_hmac.result().code();

        // verify the message tag
        let mut verifier = Hmac::<Sha1>::new_varkey(&key).expect("HMAC can take key of any size");
        verifier.input(&msg);
        assert!(verifier.verify(&result_code).is_ok());
    }

    #[test]
    fn insecure_compare_correctness() {
        assert!(!insecure_compare(b"abcdefghijklmnopqrstuvwxyz1234567890", b"abcde"));
        assert!(insecure_compare(
            b"abcdefghijklmnopqrstuvwxyz1234567890",
            b"abcdefghijklmnopqrstuvwxyz1234567890"
        ));
        assert!(!insecure_compare(b"abc2efg", b"abcdefg"));
    }
}
