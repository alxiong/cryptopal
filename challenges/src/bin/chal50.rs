use cipher::{cbc::AES_128_CBC, Cipher};
use encoding::hex;
use openssl::symm::{Cipher as SslCipher, Crypter as SslCrypter, Mode};

const ZERO_IV: [u8; 16] = *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

fn main() {
    println!("🔓 Challenge 50");
    // forgery idea: with the key for encryption in each round of CBC
    // we could reversely deduce the input from the tag we wanted via CBC decrypt
    // by recursively reduce each round we could find an iv2 s.t. MAC(k, m2, iv2) = MAC(k, m1, iv)
    let key = b"YELLOW SUBMARINE".to_vec();
    let snippet1 = b"alert('MZA who was that?');\n".to_vec();
    let snippet2 = b"alert('Ayo, the Wu is back!');\n".to_vec();

    let cbc_cipher = AES_128_CBC::from_iv(&ZERO_IV);
    let tag = hex::hexstr_to_bytes("296b8d7cb78a243dda4d0a61d33bbdd1").unwrap();
    // make sure the hash is correctly produced
    assert_eq!(
        &cbc_cipher
            .encrypt(&key, &snippet1)
            .rchunks(16)
            .next()
            .unwrap()
            .to_vec(),
        &tag
    );
    // make sure the reduce iv logic is correct
    assert_eq!(deduce_iv(&key, &snippet1, &tag), ZERO_IV);

    let forge_iv = deduce_iv(&key, &snippet2, &tag);
    // now with a handicrafted iv, we can forge a (m2, tag) pair that sneakily pass integrity check
    let cbc_cipher = AES_128_CBC::from_iv(&forge_iv);
    if cbc_cipher
        .encrypt(&key, &snippet2)
        .rchunks(16)
        .next()
        .unwrap()
        .to_vec()
        == tag
    {
        println!("Successfully forged for script: ");
        println!("alert('Ayo, the Wu is back!');\\n");
    }
}

fn cbc_pad(msg: &[u8]) -> Vec<u8> {
    let mut padded = msg.to_vec();
    if msg.len() % 16 == 0 {
        padded.append(&mut vec![16 as u8; 16]);
    } else {
        let padding_len = 16 - msg.len() % 16;
        padded.append(&mut vec![padding_len as u8; padding_len as usize]);
    }
    padded
}

// E(k, last_tag XOR m) = tag
// given tag output of this CBC round, and the message block, output the tag of last round
fn last_tag(key: &[u8], tag: &[u8], m: &[u8]) -> Vec<u8> {
    let mut decrypter = SslCrypter::new(SslCipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    decrypter.pad(false); // disable padding from aes_128_ecb
    let mut pt: Vec<u8> = vec![0; 32];
    let mut count = decrypter.update(&tag, &mut pt).unwrap();
    count += decrypter.finalize(&mut pt[count..]).unwrap();
    pt.truncate(count);

    xor::xor(&m, &pt).unwrap()
}

fn deduce_iv(key: &[u8], msg: &[u8], tag: &[u8]) -> Vec<u8> {
    // skip checking whether msg is already padded
    let padded = cbc_pad(&msg);
    let mut last = tag.to_owned();
    for m in padded.rchunks(16) {
        last = last_tag(&key, &last, &m);
    }
    last
}
