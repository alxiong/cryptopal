pub use super::{random_bytes, MAC};
use rand;
pub use sha1::{Digest, Sha1};

#[derive(Default)]
pub struct SecretPrefixMac {
    key: Vec<u8>,
}

impl SecretPrefixMac {
    pub fn new() -> SecretPrefixMac {
        SecretPrefixMac {
            key: random_bytes(rand::random::<u8>() as u32),
        }
    }

    /// Signed MAC on msg without padding
    pub fn raw_sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut h = Sha1::new();
        h.input(&[self.key.clone(), msg.to_vec()].concat());
        h.raw_result().to_vec()
    }

    /// Sign a MAC and return Sha1 (its internal states)
    pub fn transparent_sign(&self, msg: &[u8]) -> Sha1 {
        let mut h = Sha1::new();
        h.input([self.key.clone(), msg.to_vec()].concat());
        h
    }
}

impl MAC for SecretPrefixMac {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut h = Sha1::new();
        h.input([self.key.clone(), msg.to_vec()].concat());
        h.result().to_vec()
    }

    fn verify(&self, msg: &[u8], tag: &[u8]) -> bool {
        let mut h = Sha1::new();
        h.input([self.key.clone(), msg.to_vec()].concat());
        h.result().to_vec() == tag.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mac_correctness() {
        let msg = "any message".as_bytes().to_vec();
        let mac = SecretPrefixMac::new();
        assert!(mac.verify(&msg, &mac.sign(&msg)));
    }

    #[test]
    fn mac_unforgeable() {
        let msg = "yellow submarine".as_bytes().to_vec();
        let mac = SecretPrefixMac::new();
        // test you can't find a m' to collide on the same tag
        for _ in 0..1000 {
            assert_eq!(mac.verify(&random_bytes(16), &mac.sign(&msg)), false);
        }
        // test you can't find a tag of m without knowing the key
        for _ in 0..1000 {
            assert_eq!(mac.verify(&msg, &random_bytes(20)), false);
        }
    }
}
