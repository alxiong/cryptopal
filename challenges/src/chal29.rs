use sha1::{Digest, Sha1};

/// returns the hash digest of msg || PB || ext
/// where PB is padding block, ext is extension msg
fn extension_attack(msg: &[u8], ext: &[u8]) -> Vec<u8> {
    let padding = get_md_padding(&msg);
    let mut h = Sha1::new();
    h.input(&[msg, &padding].concat());
    h.input(ext);
    h.result().to_vec()
}

#[allow(clippy::identity_op)]
/// computes the Merkle-Damgard padding SHA1 produces
pub fn get_md_padding(msg: &[u8]) -> Vec<u8> {
    let bits = msg.len() * 8;
    let extra = [
        (bits >> 56) as u8,
        (bits >> 48) as u8,
        (bits >> 40) as u8,
        (bits >> 32) as u8,
        (bits >> 24) as u8,
        (bits >> 16) as u8,
        (bits >> 8) as u8,
        (bits >> 0) as u8,
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
    fn verify_extension_attack() {
        let msg = "The quick brown fox jumps over the lazy dog".as_bytes();
        let ext = "append whatever I want".as_bytes();
        let forged_tag = extension_attack(&msg, &ext);

        let mut h = Sha1::new();
        let padding = get_md_padding(&msg);
        h.input(&msg);
        h.input(&padding);
        h.input(&ext);
        let expected_tag = h.result().to_vec();

        assert_eq!(forged_tag, expected_tag);
    }
}
