use challenges::{chal28::*, chal29::*};

fn main() {
    println!("🔓 Challenge 29");
    let mac = SecretPrefixMac::new();
    let key_size = deduce_key_size(&mac).unwrap();
    let original_msg =
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

    let padding = get_md_padding(&random_bytes(key_size + original_msg.len() as u32));
    let extension = b";admin=true";
    let mut h = mac.transparent_sign(&[original_msg, &padding].concat());
    h.update(&extension[..]);
    let forged_tag = h.digest().bytes();

    assert!(mac.verify(&[original_msg, &padding, extension].concat(), &forged_tag));
    println!("Successfully forged a tag via extension attack");
}

fn deduce_key_size(mac: &SecretPrefixMac) -> Option<u32> {
    let ref_tag = mac.sign(&[]);
    for key_size in 0..256 {
        let padding = get_md_padding(&random_bytes(key_size));
        if mac.raw_sign(&padding) == ref_tag {
            return Some(key_size);
        }
    }
    None
}
