use rand::{self, RngCore};

pub fn random_bytes(size: u32) -> Vec<u8> {
    let mut bytes = vec![0 as u8; size as usize];
    rand::thread_rng().fill_bytes(&mut bytes[..]);
    bytes
}

pub fn random_bytes_array(arr: &mut [u8]) {
    for i in 0..arr.len() {
        arr[i] = rand::random::<u8>();
    }
}
