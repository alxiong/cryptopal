#![allow(non_snake_case)]
use challenges::{chal36, SrpClient};
use dh::mod_p::Dh;
use hmac::{Hmac, Mac};
use num::{BigUint, Zero};
use sha2::{Digest, Sha256};
use std::thread;
use std::time::Duration;

const EMAIL: &str = "outlook@gmail.com";

struct ClientState {
    A: BigUint,
}

impl ClientState {
    pub fn new(A: BigUint) -> ClientState {
        ClientState { A }
    }
}

impl SrpClient for ClientState {
    fn init(&mut self) -> (String, BigUint) {
        (EMAIL.to_string(), self.A.clone())
    }
    fn kex(&mut self, salt: &[u8], _B: &BigUint) -> Vec<u8> {
        let S = BigUint::zero();
        let mut hasher = Sha256::new();
        hasher.input(S.to_bytes_le());
        let K = hasher.result().to_vec();

        let mut hmac_sha256 = Hmac::<Sha256>::new_varkey(&K).expect("HMAC can take varkey");
        hmac_sha256.input(&salt);
        hmac_sha256.result().code().to_vec()
    }
}

#[tokio::main]
async fn main() {
    println!("🔓 Challenge 37");
    let _ = thread::spawn(chal36::launch_server);
    thread::sleep(Duration::from_secs(2)); // make sure the server is launched

    let mut client = ClientState::new(BigUint::zero());
    if chal36::srp_run(&mut client).await.unwrap() {
        println!("\n\n✔ ️️Succesfully bypass the login\n\n");
    } else {
        println!("\n\n❌ Failed to attack\n\n");
    }

    let dh = Dh::new();
    let mut client = ClientState::new(dh.p);
    if chal36::srp_run(&mut client).await.unwrap() {
        println!("\n\n✔ ️️Succesfully bypass the login TWICE!");
    }
}
