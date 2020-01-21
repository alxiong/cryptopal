use challenges::chal18::Key;
use cryptanalysis::{freq_analysis, transpose_block};

fn main() {
    println!("🔓 Challenge 19");
    let key = Key::new();
    let ct_arr = key.successive_encryption();
    break_using_substitution(&ct_arr);
    println!("😥 The result is horrendous, only very small portion is readable. The reasons are two folds:️");
    println!("  1. the 40 plaintexts are too few for substitution cipher to have good freqency analytical guess");
    println!("  2. the trigram isn't perfect, thus evaluation of the actual key in key_stream might be off");
}

fn break_using_substitution(ct_arr: &[Vec<u8>]) {
    let ct_transposed = transpose_block(&ct_arr);
    let mut pt_transposed: Vec<Vec<u8>> = vec![];
    for ct in ct_transposed.iter() {
        pt_transposed.push(
            freq_analysis::break_single_byte_xor(&ct)
                .as_bytes()
                .to_vec(),
        );
    }
    let pt = transpose_block(&pt_transposed);
    let pt: Vec<_> = pt
        .into_iter()
        .map(|bytes| String::from_utf8(bytes).unwrap_or_default())
        .collect();
    println!("pt: {:#?}", pt);
}
