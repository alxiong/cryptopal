use super::mod_inv;
use num::bigint::RandBigInt;
use num::{BigUint, One, Zero};
use sha1::{Digest, Sha1};

#[derive(Clone)]
/// group of public parameter for a DSA instance
pub struct DsaPublicParam {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
}

/// represent a DSA signature
pub struct DsaSignature {
    pub r: BigUint,
    pub s: BigUint,
}

impl DsaPublicParam {
    /// non-comprehensive sanity check for the parameter
    pub fn check(&self) -> bool {
        let q_bits = self.q.bits();
        let p_bits = self.p.bits();
        // NOTE: only support for SHA-1 for now which has 160 bit.
        !(q_bits > 160 || q_bits >= p_bits || (&self.p - BigUint::one()) % &self.q != BigUint::zero())
    }
}

/// representing DSA key pair
pub struct DsaKeyPair {
    pub pub_param: DsaPublicParam,
    pub pub_key: BigUint,
    pri_key: BigUint,
}

impl DsaKeyPair {
    /// public parameter generation (hard-coded) and per-user key generation
    pub fn key_gen() -> Self {
        let pub_param = DsaPublicParam {
            p: BigUint::parse_bytes(
                &b"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65e\
                   ac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc5\
                   65f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232\
                   c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1"
                    .to_vec(),
                16,
            )
            .unwrap(),
            q: BigUint::parse_bytes(&b"f4f47f05794b256174bba6e9b396a7707e563c5b".to_vec(), 16).unwrap(),
            g: BigUint::parse_bytes(
                &b"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa40\
                   46c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025\
                   e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c88\
                   7892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291"
                    .to_vec(),
                16,
            )
            .unwrap(),
        };
        assert!(pub_param.check()); // making sure the paramter given is sensible

        let mut rng = rand::thread_rng();
        let pri_key = rng.gen_biguint_range(&BigUint::one(), &pub_param.q);
        let pub_key = pub_param.g.modpow(&pri_key, &pub_param.p);
        DsaKeyPair {
            pub_param,
            pub_key,
            pri_key,
        }
    }

    /// returns the public key for key distribution
    pub fn get_pub_key(&self) -> DsaPubKey {
        DsaPubKey {
            pub_param: self.pub_param.clone(),
            pub_key: self.pub_key.clone(),
        }
    }

    /// signing a message using DSA
    pub fn sign(&self, msg: &[u8]) -> DsaSignature {
        let mut s = BigUint::zero();
        let mut r = BigUint::zero();
        while s == BigUint::zero() {
            let mut rng = rand::thread_rng();
            let k = rng.gen_biguint_range(&BigUint::one(), &self.pub_param.q);

            while r == BigUint::zero() {
                r = self.pub_param.g.modpow(&k, &self.pub_param.p) % &self.pub_param.q;
            }

            let hash = hash_msg(&msg);
            s = (mod_inv(&k, &self.pub_param.q).unwrap() * (hash + &self.pri_key * &r)) % &self.pub_param.q;
        }
        DsaSignature { r, s }
    }
}

fn hash_msg(msg: &[u8]) -> BigUint {
    let mut h = Sha1::default();
    h.input(&msg);
    let hash_bytes = h.result().to_vec();
    BigUint::from_bytes_be(&hash_bytes)
}

pub struct DsaPubKey {
    pub pub_param: DsaPublicParam,
    pub pub_key: BigUint,
}

impl DsaPubKey {
    /// Verify a DSA signature
    pub fn sig_verify(&self, msg: &[u8], sig: &DsaSignature) -> bool {
        let p = &self.pub_param.p;
        let q = &self.pub_param.q;
        let g = &self.pub_param.g;
        // verify that 0 < r < q and 0 < s < q
        if &sig.r >= q || &sig.s >= q {
            return false;
        }

        let w = mod_inv(&sig.s, q).expect("Invalid DSA Signature");
        let hash = hash_msg(&msg);

        let u_1 = (&hash * &w) % q;
        let u_2 = (&sig.r * &w) % q;
        let v = ((g.modpow(&u_1, p) * &self.pub_key.modpow(&u_2, p)) % p) % q;

        v == sig.r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dsa_correctness() {
        let msg = b"whatever message".to_vec();
        let dsa_key = DsaKeyPair::key_gen();
        let dsa_pub_key = dsa_key.get_pub_key();

        let sig = dsa_key.sign(&msg);
        assert_eq!(dsa_pub_key.sig_verify(&msg, &sig), true);
    }
}
