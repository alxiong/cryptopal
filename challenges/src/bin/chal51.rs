use challenges::random_bytes;
use cipher::Mode;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::prelude::*;

fn main() {
    println!("🔓 Challenge 51");
    let content = b"body line1 \nbody line2\n";
    oracle_ctr_zlib(&content.to_vec());
}

// compression oracle, using zlib for compression, CTR mode stream cipher
fn oracle_ctr_zlib(content: &[u8]) -> usize {
    // step 1. format request
    let req = format!(
        "POST / HTTP/1.1\n\
         Host: hapless.com\n\
         Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n\
         Content-Length: {}\n\
         {}",
        content.len(),
        String::from_utf8_lossy(&content),
    );
    // step 2. compress formatted request
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(req.as_bytes())
        .expect("Failed to compress, internal error");
    let compressed_req = e.finish().unwrap();
    // step 3. encrypt compressed bytes
    let key = random_bytes(16);
    let cipher = cipher::new(Mode::CTR);
    let ct = cipher.encrypt(&key, &compressed_req);
    // step 4. return length of ciphertext
    ct.len()
}
