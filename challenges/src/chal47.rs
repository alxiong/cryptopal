use super::chal39::{RsaKeyPair, RsaPubKey};
use num::{bigint::RandBigInt, pow::Pow, BigUint, FromPrimitive, One, Zero};

#[allow(clippy::many_single_char_names)]
/// Implementation of BB'98 CCA padding oracle attack, returns the decrypted message
pub fn rsa_padding_oracle_attack(pk: &RsaPubKey, ct: &BigUint, oracle: &Oracle) -> BigUint {
    let mut rng = rand::thread_rng();
    // B = 2 ^ (n - 16)
    let B = BigUint::from_u32(2).unwrap().pow(&pk.n.bits() - 16);

    // Step 1: Blinding
    let mut s_0 = BigUint::zero();
    while s_0 == BigUint::zero() || !oracle.oracle_query(&(ct * pk.encrypt(&s_0))) {
        s_0 = rng.gen_biguint_below(&pk.n);
    }

    // Step 2: Adaptive chosen s value search
    // Step 3: Narrowing the solution range
    // Step 4: Terminate or Repeat (back to step 2)
    BigUint::one()
}

/// Bleichenbacher oracle
pub struct Oracle {
    key_pair: RsaKeyPair,
}

impl Oracle {
    pub fn new(key_pair: &RsaKeyPair) -> Oracle {
        Oracle {
            key_pair: key_pair.clone(),
        }
    }

    pub fn oracle_query(&self, ct: &BigUint) -> bool {
        self.key_pair.priKey.bb_oracle(&ct)
    }
}
