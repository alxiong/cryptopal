use super::chal39::{RsaKeyPair, RsaPubKey};
use num::{BigUint, One, Zero};

/// input an RSA public key, the ciphertext, and the oracle
/// outpus the decryption
pub fn rsa_parity_oracle_attack(pk: &RsaPubKey, ct: &BigUint, oracle: &Oracle) -> BigUint {
    // inclusive upper and lower bounds
    let mut upper = &pk.n - BigUint::one();
    let mut lower = BigUint::zero();
    let two = BigUint::parse_bytes(b"2", 10).unwrap();
    let mut multiplier = two.clone();

    while upper > lower {
        let mid = (&upper + &lower) / &two;
        let rem = (&upper + &lower) % &two;

        if oracle.parity_query(&(ct * pk.encrypt(&multiplier))) {
            upper = mid;
        } else if rem == BigUint::zero() {
            lower = mid;
        } else {
            lower = mid + BigUint::one();
        }

        multiplier *= two.clone();
    }

    assert_eq!(upper, lower);
    lower
}

// using a struct because parity oracle requires private keys which should be private field, yet
// oracle is a public function
/// An RSA parity oracle
pub struct Oracle {
    key_pair: RsaKeyPair,
}

impl Oracle {
    /// initialize the oracle with an RSA keypair (priKey specifically)
    pub fn new(key_pair: &RsaKeyPair) -> Oracle {
        Oracle {
            key_pair: key_pair.clone(),
        }
    }

    /// public facing parity query API
    pub fn parity_query(&self, ct: &BigUint) -> bool {
        self.key_pair.priKey.parity(&ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parity_oracle_attack() {
        let key_pair = RsaKeyPair::new_1024_rsa();
        let oracle = Oracle::new(&key_pair);

        let msg = BigUint::parse_bytes(b"314159", 10).unwrap();
        let ct = key_pair.pubKey.encrypt(&msg);

        assert_eq!(rsa_parity_oracle_attack(&key_pair.pubKey, &ct, &oracle), msg);
    }
}
