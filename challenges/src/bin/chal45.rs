use challenges::chal43::{DsaKeyPair, DsaSignature};
use num::{BigUint, One, Zero};

fn main() {
    println!("🔓 Challenge 45");

    let target_msg_1 = b"Hello, World".to_vec();
    let target_msg_2 = b"Goodbye, World".to_vec();

    println!("\n👻 Use generator of value 0 mod p");
    let dsa_key = DsaKeyPair::key_gen_with_generator(&BigUint::zero());
    let msg = b"any message".to_vec();
    let sig = dsa_key.broken_sign(&msg); // sign without checking r, s for zero value
    let pk = dsa_key.get_pub_key();

    assert!(pk.sig_verify(&msg, &sig));
    // for any random message, the verificaiton will checks out with this sig:
    if pk.sig_verify(&target_msg_1, &sig) && pk.sig_verify(&target_msg_2, &sig) {
        println!("🤦‍ ️Oops, the signatures on target messages pass verification");
    }

    println!("\n👻 Use generator of value 1 mod p");
    let dsa_key = DsaKeyPair::key_gen_with_generator(&(&pk.pub_param.p + BigUint::one()));
    let pk = dsa_key.get_pub_key();
    // z = 1, r = (y mod p) mod q, s = r;
    let r = (&pk.pub_key % &pk.pub_param.p) % &pk.pub_param.q;
    let magic_sig = DsaSignature { r: r.clone(), s: r };
    if pk.sig_verify(&target_msg_1, &magic_sig) && pk.sig_verify(&target_msg_2, &magic_sig) {
        println!("🤦‍ ️Oops, the signatures on target messages pass verification AGAIN");
    }
}
