use challenges::{
    chal39::RsaKeyPair,
    chal46::{rsa_parity_oracle_attack, Oracle},
};
use encoding::base64::{Base64, FromStr};
use num::BigUint;

fn main() {
    println!("🔓 Challenge 46");

    let rsa_keys = RsaKeyPair::new_1024_rsa();
    let oracle = Oracle::new(&rsa_keys);

    let pt_hexstr = encoding::base64_to_hex(
        Base64::from_str(
            &"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==",
        )
        .unwrap(),
    );
    let pt = BigUint::parse_bytes(&pt_hexstr.as_bytes(), 16).unwrap();
    let ct = rsa_keys.pubKey.encrypt(&pt);

    println!("Let the cracking begin ... (took me ~ 5 min on my laptop)");
    let decrypted_bytes = rsa_parity_oracle_attack(&rsa_keys.pubKey, &ct, &oracle).to_bytes_be();
    let decrypted = String::from_utf8_lossy(&decrypted_bytes);
    println!("Decrypted message: {}", decrypted);
}
