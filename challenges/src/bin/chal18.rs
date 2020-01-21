use cipher::{ctr::AES_128_CTR, Cipher};
use encoding::base64::*;

fn main() {
    println!("🔓 Challenge 18");
    let ctr_cipher = AES_128_CTR::new_with_nonce(0 as u64);
    let ct_base64 = Base64::from_str(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
    )
    .unwrap();
    let ct = ct_base64.as_bytes();

    let pt = ctr_cipher.decrypt(&b"YELLOW SUBMARINE"[..], &ct);
    println!("Decrypted: {:?}", String::from_utf8(pt).unwrap());
}
