use cryptanalysis::freq_analysis;
use encoding::hex;

fn main() {
    println!("🔓 Challenge 3");
    let decrypted = freq_analysis::break_single_byte_xor(
        &hex::hexstr_to_bytes(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        )
        .unwrap(),
    );
    println!("decrypted message: {}", decrypted);
}
