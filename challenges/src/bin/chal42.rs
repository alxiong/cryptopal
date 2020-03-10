use challenges::chal39::{RsaKeyPair, RsaPubKey, SHA1_PKCS1_DIGESTINFO_PREFIX};
use num::pow::Pow;
use num::{BigUint, One};
use sha1::{Digest, Sha1};
use std::cmp::Ordering;

fn main() {
    println!("🔓 Challenge 42");

    let msg = b"hi mom".to_vec();
    let pk = RsaKeyPair::default().pubKey;
    let forged_sig = forgey_attack(&msg, &pk);

    assert!(pk.broken_sig_verify(&msg, &forged_sig));
    println!("Successfully forged a signature!");
}

fn forgey_attack(msg: &[u8], pk: &RsaPubKey) -> Vec<u8> {
    let mod_byte = pk.n.bits() / 8;

    let mut h = Sha1::default();
    h.input(&msg);
    let hash = h.result().to_vec();

    let forged_pt_prefix = b"\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff".to_vec();
    let forged_pt_payload = [b"\x00".to_vec(), SHA1_PKCS1_DIGESTINFO_PREFIX.to_vec(), hash].concat();
    let garbage_len_max = mod_byte - forged_pt_prefix.len() - forged_pt_payload.len();

    for garbage_len in 0..garbage_len_max + 1 {
        let extra_xff_len = garbage_len_max - garbage_len;
        let forged_pt_min = BigUint::from_bytes_be(
            &[
                forged_pt_prefix.clone(),
                vec![255 as u8; extra_xff_len].to_vec(),
                forged_pt_payload.clone(),
                vec![0 as u8; garbage_len],
            ]
            .concat(),
        );
        let forged_pt_max = &forged_pt_min + (BigUint::one() << (garbage_len * 8));
        if let Some(cub) = next_cub(&forged_pt_min, &forged_pt_max) {
            return BigUint::to_bytes_be(&cub.cbrt());
        }
    }
    panic!("Failed!");
}

// return the next perfect cubic number between [a, b)
fn next_cub(a: &BigUint, b: &BigUint) -> Option<BigUint> {
    let cbrt = a.cbrt();
    match cbrt.pow(3 as u32).cmp(&a) {
        Ordering::Equal => Some(a.to_owned()),
        Ordering::Greater => panic!("should never happen"),
        Ordering::Less => {
            let next = (cbrt + BigUint::one()).pow(3 as u32);
            match next.cmp(&b) {
                Ordering::Less => Some(next),
                _ => None,
            }
        }
    }
}
