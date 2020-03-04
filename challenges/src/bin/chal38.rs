#![allow(non_snake_case)]

use challenges::{chal38, random_bytes};
use dh::{mod_p::Dh, DH};
use hmac::{Hmac, Mac};
use num::bigint::RandBigInt;
use sha2::{Digest, Sha256};
use std::thread;
use std::time::Duration;

const DICTIONARY: &[&[u8]] = &[
    b"dad birthday",
    b"mom birthday",
    b"my birthday",
    b"username",
    b"password",
    b"1234567890",
    b"password_is_username",
    b"username_is_password",
    b"111111111",
];

#[tokio::main]
async fn main() {
    println!("🔓 Challenge 38");
    let _ = thread::spawn(chal38::launch_server);
    thread::sleep(Duration::from_secs(2));

    if normal_run().await.unwrap() {
        println!("\n\n✔ ️️Succesfully established a secure channel!\n\n");
    }

    if mitm_dict_attack().unwrap() == chal38::PASSWORD {
        println!("\n\n😈 ️Succesfully extract the password!\n\n");
    }
}

async fn normal_run() -> chal38::Result<bool> {
    let mut client = chal38::ClientState::new();

    chal38::query_init().await?;
    let (email, A) = client.init();
    let (salt, B, u) = chal38::query_kex(&email, &A).await?;
    let tag = client.kex(&salt, &B, &u);
    let success = chal38::query_verify(&tag).await?;
    chal38::query_reset().await?;

    if success {
        Ok(true)
    } else {
        Ok(false)
    }
}

// offline dictionary attack will only be interaction between the client
fn mitm_dict_attack() -> Option<String> {
    println!("🕮 Starting offline, Man-in-the-Middle, dictionary attack ...");
    let mut client = chal38::ClientState::new();

    // C -> Eve : email, A
    let (_email, A) = client.init();

    // Eve: random (salt, b, B, u)
    let salt = random_bytes(32);
    let dh = Dh::new();
    let (b, B) = dh.key_gen();
    let mut rng = rand::thread_rng();
    let u = rng.gen_biguint(128);

    // Eve -> C, then Client returns HMAC tag
    let tag = client.kex(&salt, &B, &u);

    // Now Eve use dictionary attack on potential password candidates with the HMAC tag
    for pwd in DICTIONARY {
        let mut hasher = Sha256::new();
        hasher.input([salt.clone(), pwd.to_vec()].concat());
        let x = chal38::bytes_to_biguint(&hasher.result().to_vec());
        let v = dh.exp(&x);

        let S = (A.clone() * v.modpow(&u, &dh.p)).modpow(&b, &dh.p);

        let mut hasher = Sha256::new();
        hasher.input(S.to_bytes_le());
        let K = hasher.result().to_vec();

        let mut hmac_sha256 = Hmac::<Sha256>::new_varkey(&K).expect("HMAC can take varkey");
        hmac_sha256.input(&salt);

        if hmac_sha256.verify(&tag).is_ok() {
            return Some(String::from_utf8(pwd.to_vec()).unwrap());
        }
    }

    None
}
