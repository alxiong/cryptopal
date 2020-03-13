use challenges::chal39::RsaKeyPair;
use challenges::chal48::{rsa_padding_oracle_attack, Oracle};

fn main() {
    println!("🔓 Challenge 47");
    let rsa_keys = RsaKeyPair::new_256_rsa();
    let mut oracle = Oracle::new(&rsa_keys);

    let msg = b"kick it, CC".to_vec();
    let m = rsa_keys.pubKey.pkcs_pad(&msg);
    let ct = &rsa_keys.pubKey.encrypt(&m);

    let decrypted = rsa_padding_oracle_attack(&rsa_keys.pubKey, &ct, &mut oracle);
    assert_eq!(decrypted, m);
}
