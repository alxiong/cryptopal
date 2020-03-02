// This is a simple variant of DHKE, where multiplicative group of integers mod p is used
pub use super::DH;
use num::{bigint::RandBigInt, BigUint};

#[derive(Default, Debug)]
pub struct Dh {
    pub g: BigUint,
    pub p: BigUint,
}

impl Dh {
    pub fn new() -> Dh {
        Dh {
            g: BigUint::new(vec![2]),
            p: BigUint::parse_bytes(
                b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
                  e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
                  3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
                  6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
                  24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
                  c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
                  bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
                  fffffffffffff",
                16,
            )
            .unwrap(),
        }
    }
    pub fn rand_elm(&self) -> BigUint {
        let mut rng = rand::thread_rng();
        rng.gen_biguint_below(&self.p)
    }
}

impl DH for Dh {
    type GroupElement = BigUint;
    fn check_elm(&self, elm: &Self::GroupElement) -> bool {
        if *elm > self.p {
            return false;
        }
        true
    }

    fn get_generator(&self) -> Self::GroupElement {
        self.g.clone()
    }

    fn exp(&self, e: &BigUint) -> Self::GroupElement {
        self.g.modpow(e, &self.p)
    }

    fn key_gen(&self) -> (BigUint, Self::GroupElement) {
        let mut rng = rand::thread_rng();
        let pri_key = rng.gen_biguint_below(&self.p);

        let pub_key = self.exp(&pri_key);
        assert!(self.check_elm(&pub_key));
        (pri_key, pub_key)
    }

    fn kex(&self, sk: &BigUint, pk: &Self::GroupElement) -> Self::GroupElement {
        assert!(self.check_elm(&pk));
        pk.modpow(sk, &self.p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_works() {
        let dh = Dh::new();
        let (a_sk, a_pk) = dh.key_gen();
        let (b_sk, b_pk) = dh.key_gen();
        assert_eq!(dh.kex(&a_sk, &b_pk), dh.kex(&b_sk, &a_pk));
    }
}
