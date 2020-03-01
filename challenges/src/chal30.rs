pub use super::{random_bytes, MAC};
pub use md4::{Digest, Md4};

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

    pub fn raw_sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut h = Md4::new();
        h.input([self.key.clone(), msg.to_vec()].concat());
        h.result_without_padding()[..].to_vec()
    }

    pub fn transparent_sign(&self, msg: &[u8]) -> Md4 {
        let mut h = Md4::new();
        h.input([self.key.clone(), msg.to_vec()].concat());
        h
    }
}

impl MAC for SecretPrefixMac {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut h = Md4::new();
        h.input([self.key.clone(), msg.to_vec()].concat());
        h.result()[..].to_vec()
    }

    fn verify(&self, msg: &[u8], tag: &[u8]) -> bool {
        let mut h = Md4::new();
        h.input([self.key.clone(), msg.to_vec()].concat());
        h.result()[..] == *tag
    }
}

#[allow(clippy::identity_op)]
pub fn get_md_padding(msg: &[u8]) -> Vec<u8> {
    let bits = msg.len() * 8;
    let extra = [
        (bits >> 0) as u8,
        (bits >> 8) as u8,
        (bits >> 16) as u8,
        (bits >> 24) as u8,
        (bits >> 32) as u8,
        (bits >> 40) as u8,
        (bits >> 48) as u8,
        (bits >> 56) as u8,
    ];
    let mut padding = vec![0 as u8; 128];
    let blocklen = msg.len() % 64 as usize;
    padding[blocklen] = 0x80;

    if blocklen < 56 {
        padding[56..64].clone_from_slice(&extra);
        padding[blocklen..64].to_vec()
    } else {
        padding[120..128].clone_from_slice(&extra);
        padding[blocklen..128].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mac_correctness() {
        let msg = b"any message".to_vec();
        let mac = SecretPrefixMac::new();
        assert!(mac.verify(&msg, &mac.sign(&msg)));
    }
    #[test]
    fn mac_unforgeable() {
        let msg = b"yellow submarine".to_vec();
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
    #[test]
    fn verify_md4_md_padding() {
        let msg = "The quick brown fox jumps over the lazy dog".as_bytes();
        let padding = get_md_padding(&msg);

        let mut h1 = Md4::new();
        h1.input([msg, &padding].concat());
        let d1 = h1.result_without_padding();

        let mut h2 = Md4::new();
        h2.input(&msg);
        let d2 = h2.result();

        assert_eq!(d1, d2);
    }
}
