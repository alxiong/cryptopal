use std::cmp::Ordering::Equal;
use std::collections::HashMap;

#[allow(dead_code)]
// source: https://norvig.com/mayzner.html
static LETTER_FREQ: [(u8, f32); 26] = [
    (b'e', 0.1249),
    (b't', 0.0928),
    (b'a', 0.0804),
    (b'o', 0.0764),
    (b'i', 0.0757),
    (b'n', 0.0723),
    (b's', 0.0651),
    (b'r', 0.0628),
    (b'h', 0.0505),
    (b'l', 0.0407),
    (b'd', 0.0382),
    (b'c', 0.0334),
    (b'u', 0.0273),
    (b'm', 0.0251),
    (b'f', 0.0240),
    (b'p', 0.0214),
    (b'g', 0.0187),
    (b'w', 0.0168),
    (b'y', 0.0166),
    (b'b', 0.0148),
    (b'v', 0.0105),
    (b'k', 0.0054),
    (b'x', 0.0023),
    (b'j', 0.0016),
    (b'q', 0.0012),
    (b'z', 0.0009),
];

// source: https://mdickens.me/typing/letter_frequency.html
static CHAR_FREQ: [u8; 30] = [
    b' ', b'e', b't', b'a', b'o', b'i', b'n', b's', b'r', b'h', b'l', b'd', b'c', b'u', b'm', b'f',
    b'g', b'p', b'y', b'w', b'\n', b'b', b',', b'.', b'v', b'k', b'-', b'"', b'_', b'\'',
];

// source: http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
static TRIGRAPH_FREQ: [(&str, f32); 30] = [
    ("the", 1.81),
    ("and", 0.73),
    ("ing", 0.72),
    ("ent", 0.42),
    ("ion", 0.42),
    ("her", 0.36),
    ("for", 0.34),
    ("tha", 0.33),
    ("nth", 0.33),
    ("int", 0.32),
    ("ere", 0.31),
    ("tio", 0.31),
    ("ter", 0.30),
    ("est", 0.28),
    ("ers", 0.28),
    ("ati", 0.26),
    ("hat", 0.26),
    ("ate", 0.25),
    ("all", 0.25),
    ("eth", 0.24),
    ("hes", 0.24),
    ("ver", 0.24),
    ("his", 0.24),
    ("oft", 0.22),
    ("ith", 0.21),
    ("fth", 0.21),
    ("sth", 0.21),
    ("oth", 0.21),
    ("res", 0.21),
    ("ont", 0.20),
];

// Evaluation function on the likelihood of a plaintext is a real English text.
// More occurance of frequent trigraph pattern, the higher the score, which means more likely
fn plaintext_eval(pt: &str) -> f32 {
    let mut score: f32 = 0.0;
    for (pattern, freq) in TRIGRAPH_FREQ.iter() {
        score += pt.matches(pattern).count() as f32 * freq;
    }
    score
}

// TODO: improve the reliability and accuracy of this function.
/// Break substitution cipher XORed with one single byte
pub fn break_single_byte_xor(ct: &[u8]) -> String {
    // count the occurance of each char
    let mut ct_occurance: HashMap<u8, u32> = HashMap::new();
    for byte in ct.iter() {
        let ctr = ct_occurance.entry(*byte).or_insert(0);
        *ctr += 1;
    }

    // sort ct_occrance in descending order
    let mut ct_freq: Vec<(u8, u32)> = vec![];
    for (&byte, &count) in ct_occurance.iter() {
        ct_freq.push((byte, count));
    }
    ct_freq.sort_by(|a, b| b.1.cmp(&a.1));

    // try to map the most frequent letter in ct (ciphertext) with the letters in
    // CHAR_FREQ sequentially and get a score of such hypothesis
    let mut pt_candidates: Vec<(String, f32)> = vec![];
    for &c in CHAR_FREQ.iter() {
        let xor_diff = ct_freq[0].0 ^ c;
        let pt = xor::xor(&ct, &vec![xor_diff; ct.len()][..]).unwrap_or_else(|_| vec![]);
        let pt = String::from_utf8(pt).unwrap_or_default();
        let score = plaintext_eval(&pt);
        pt_candidates.push((pt, score));
    }

    // sort all candidates based on their score and return the one with the highest socre
    pt_candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Equal));
    pt_candidates[0].0.clone()
}
