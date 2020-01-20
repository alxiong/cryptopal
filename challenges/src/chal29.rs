use sha1::Sha1;

/// returns the hash digest of msg || PB || ext
/// where PB is padding block, ext is extension msg
fn extension_attack(msg: &[u8], ext: &[u8]) -> Vec<u8> {
    let padding = get_md_padding(&msg);
    let mut h = Sha1::new();
    h.update(&[msg, &padding].concat());
    h.update(ext);
    h.digest().bytes().to_vec()
}

// computes the Merkle-Damgard padding SHA1 produces
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
    fn verify_get_md_padding() {
        let msg = "The quick brown fox jumps over the lazy dog".as_bytes();
        let padding = get_md_padding(&msg);
        let mut h1 = Sha1::new();
        let d1 = h1.digest_from_padded_input(&[msg, &padding].concat());

        let mut h2 = Sha1::new();
        h2.update(&msg);
        let d2 = h2.digest();

        assert_eq!(d1.data, d2.data);
    }

    #[test]
    fn verify_extension_attack() {
        let msg = "The quick brown fox jumps over the lazy dog".as_bytes();
        let ext = "append whatever I want".as_bytes();
        let forged_tag = extension_attack(&msg, &ext);

        let mut h = Sha1::new();
        let padding = get_md_padding(&msg);
        h.update(&msg);
        h.update(&padding);
        h.update(&ext);
        let expected_tag = h.digest().bytes();

        assert_eq!(forged_tag, expected_tag);
    }
}
