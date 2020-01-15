use prng::mt19937::{MT19937Rng, RngCore};
use rand::{self, Rng};
use std::thread;
use std::time::{Duration, SystemTime};

fn main() {
    println!("🔓 Challenge 22");
    println!(
        "Ah! Cracked seed is: {}",
        crack_seed(delayed_rng()).unwrap()
    );
}

fn delayed_rng() -> u32 {
    fn wait() {
        let mut rng = rand::thread_rng();
        let rand_wait = Duration::from_secs(rng.gen_range(40, 1000));
        // use the following when testing
        // let rand_wait = Duration::from_secs(rng.gen_range(0, 3));
        thread::sleep(rand_wait);
    }

    wait();
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    println!("🤫 Whisper: the seed is: {}", seed);
    let mut mt_rng = MT19937Rng::new(seed as u32);
    wait();
    mt_rng.next_u32()
}

fn crack_seed(output: u32) -> Option<u32> {
    // the seed is within 2000 sec ago
    let candidate = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
        - 3000;

    for i in 0..3000 {
        let mut rng = MT19937Rng::new(candidate + i);
        if rng.next_u32() == output {
            return Some(candidate + i);
        }
    }
    None
}
