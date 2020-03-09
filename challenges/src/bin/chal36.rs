#![allow(non_snake_case)]
use challenges::{
    chal36::{self, *},
    mod_sub, SrpClient,
};
use dh::{mod_p::Dh, DH};
use hmac::{Hmac, Mac};
use num::BigUint;
use sha2::{Digest, Sha256};
use std::thread;
use std::time::Duration;

const EMAIL: &str = "outlook@gmail.com";
const PASSWORD: &str = "password_is_username";

#[derive(Debug)]
struct ClientState {
    dh: Dh,
    k: u32,
    a: BigUint,
    A: BigUint,
    K: Vec<u8>,
}

impl ClientState {
    pub fn new() -> ClientState {
        ClientState {
            dh: Dh::new(),
            k: 3,
            a: BigUint::default(),
            A: BigUint::default(),
            K: vec![],
        }
    }
}
impl SrpClient for ClientState {
    /// initiate key exchange by outputing (Email, A = g ^ a)
    fn init(&mut self) -> (String, BigUint) {
        let (a, A) = self.dh.key_gen();
        self.a = a;
        self.A = A.clone();
        (EMAIL.to_string(), A)
    }
    /// perform key exchange, return HMAC tag for verification
    fn kex(&mut self, salt: &[u8], B: &BigUint) -> Vec<u8> {
        // compute u = Sha256(A || B)
        let mut hasher = Sha256::new();
        hasher.input([self.A.to_str_radix(16).as_bytes(), B.to_str_radix(16).as_bytes()].concat());
        let u = bytes_to_biguint(&hasher.result().to_vec());

        // get x = Sha256(salt || password)
        let mut hasher = Sha256::new();
        hasher.input([salt.to_owned(), PASSWORD.as_bytes().to_vec()].concat());
        let x = bytes_to_biguint(&hasher.result().to_vec());

        // derive shared session key
        let kgx = (self.k * &self.dh.exp(&x)) % &self.dh.p;
        let base = mod_sub(&B, &kgx, &self.dh.p);
        let S = base.modpow(&(&self.a + &u * &x), &self.dh.p);

        let mut hasher = Sha256::new();
        hasher.input(S.to_bytes_le());
        self.K = hasher.result().to_vec();

        // get hmac tag for verification of the ephermal shared key
        let mut hmac_sha256 = Hmac::<Sha256>::new_varkey(&self.K).expect("HMAC can take varkey");
        hmac_sha256.input(&salt);
        hmac_sha256.result().code().to_vec()
    }
}

#[tokio::main]
async fn main() {
    println!("🔓 Challenge 36");
    let _ = thread::spawn(chal36::launch_server);
    thread::sleep(Duration::from_secs(2)); // make sure the server is launched

    let mut client = ClientState::new();
    if chal36::srp_run(&mut client).await.unwrap() {
        println!("\n\n✔ ️️Succesfully established a secure channel!");
    } else {
        println!("\n\n❌ Failed to complete key exchanges");
    }
}
