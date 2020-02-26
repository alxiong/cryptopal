#![deny(clippy::all)]
use num::BigUint;

pub mod mod_p;

/// Diffie-Hellman trait contains common API for any choice of underlying cyclic group
pub trait DH {
    type GroupElement;
    /// check an element is a valid member in the group
    fn check_elm(&self, elm: &Self::GroupElement) -> bool;
    /// returns the default group generator
    fn get_generator(&self) -> Self::GroupElement;
    /// returns g^e as a group element
    fn exp(&self, e: &BigUint) -> Self::GroupElement;
    /// returns (priKey, pubKey) keypair
    fn key_gen(&self) -> (BigUint, Self::GroupElement);
    /// return shared session key
    fn kex(&self, sk: &BigUint, pk: &Self::GroupElement) -> Self::GroupElement;
}
