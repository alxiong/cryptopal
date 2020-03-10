use challenges::{chal39::RsaKeyPair, chal40::three_moduli_crt};
use num::{BigUint, FromPrimitive};

fn main() {
    println!("🔓 Challenge 40");
    let m = BigUint::from_u64(42).unwrap();
    let keys = RsaKeyPair::gen(3);
    let key0 = keys[0].pubKey.clone();
    let key1 = keys[1].pubKey.clone();
    let key2 = keys[2].pubKey.clone();

    let c0 = key0.encrypt(&m);
    let c1 = key1.encrypt(&m);
    let c2 = key2.encrypt(&m);

    // craking the m^e (m^3) mod (n0*n1*n2) using CRT
    let m_cub = three_moduli_crt(&c0, &c1, &c2, &key0.n, &key1.n, &key2.n);
    let decrypted_m = m_cub.cbrt();
    if m == decrypted_m {
        println!("Successfully crack small e RSA!");
    } else {
        println!("Something has gone wrong!");
    }
}
