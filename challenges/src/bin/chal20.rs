use challenges::chal18::Key;
use cryptanalysis::vigenere;
use encoding::hex;

fn main() {
    println!("🔓 Challenge 20");
    let key = Key::new();
    let ct_arr = key.successive_encryption();
    break_statistically(&ct_arr);
}

fn break_statistically(ct_arr: &[Vec<u8>]) {
    let mut shortest = ct_arr[0].len();
    for ct in ct_arr.iter() {
        if ct.len() < shortest {
            shortest = ct.len();
        }
    }
    let ct_truncated: Vec<_> = ct_arr
        .to_owned()
        .into_iter()
        .flat_map(|mut ct| {
            ct.truncate(shortest);
            ct
        })
        .collect();
    let key = vigenere::extract_key(&ct_truncated);
    let pt_hex = xor::repeating_xor(
        &hex::bytes_to_hexstr(&ct_truncated),
        &hex::bytes_to_hexstr(&key),
    );

    println!(
        "Decrypted: \n{}",
        String::from_utf8(hex::hexstr_to_bytes(&pt_hex).unwrap()).unwrap()
    );
}
