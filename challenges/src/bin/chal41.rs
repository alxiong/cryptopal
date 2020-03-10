use challenges::{chal39::RsaKeyPair, mod_inv};
use num::{bigint::RandBigInt, BigUint, One};

fn main() {
    println!("🔓 Challenge 41");

    let mut rng = rand::thread_rng();
    let m = rng.gen_biguint(16);
    let key_pair = RsaKeyPair::default();
    let n = key_pair.pubKey.n.clone();

    let c = key_pair.pubKey.encrypt(&m);

    // adaptive CCA attack on unpadded RSA
    let s = rng.gen_biguint_below(&n); // random number
    assert!(s > BigUint::one()); // very unlikely
    let c_prime = (key_pair.pubKey.encrypt(&s) * c) % &n;

    // submit to decryption oracle
    let m_prime = key_pair.priKey.decrypt(&c_prime);

    // calculate the original message
    let recovered_msg = (m_prime * mod_inv(&s, &n).unwrap()) % &n;
    if m == recovered_msg {
        println!("Successfully recover the plaintext encrypted using unpadded RSA!");
    }
}
