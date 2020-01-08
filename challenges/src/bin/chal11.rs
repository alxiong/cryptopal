use rand;
use rand::RngCore;

fn main() {
    println!("🔓 Challenge 11");
}

fn random_bytes(size: u32) -> Vec<u8> {
    let mut bytes = vec![0 as u8; size as usize];
    rand::thread_rng().fill_bytes(&mut bytes[..]);
    bytes
}
