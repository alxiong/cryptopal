#![feature(proc_macro_hygiene, decl_macro)]
#![feature(async_closure)]
use challenges::chal31;

use hyper::{self, Client};
use rocket::{self, get, routes};
use rocket::{
    config::{Config, Environment, LoggingLevel},
    http::{RawStr, Status},
};
use tokio;

use std::thread;
use std::time::{Duration, Instant};
// NOTE: when using HMAC-SHA1, we use the `Mac` trait defined in Hmac crate instead of the simple
// MAC trait in this crate
use encoding::hex;
use hmac::{Hmac, Mac};
use sha1::Sha1;

const HMAC_KEY: [u8; 22] = *b"whatever length secret"; // delibrately not 16 in length

#[get("/test?<file>&<signature>")]
// NOTE: for simplicity the `file` param will be the content of the file, the `signature` will be
// just generated on the value of the `file`, not an actual file.
// `signature` is hex string
fn test(file: &RawStr, signature: &RawStr) -> Status {
    let mut hmac = Hmac::<Sha1>::new_varkey(&HMAC_KEY.to_vec()).expect("HMAC can take key of any size");
    hmac.input(&file.to_string().as_bytes());
    let tag = hmac.result().code().to_vec();
    let sig_bytes = hex::hexstr_to_bytes(&signature.to_string()).unwrap_or_default();
    if chal31::insecure_compare(&tag, &sig_bytes) {
        Status::Ok
    } else {
        Status::InternalServerError
    }
}

#[tokio::main]
async fn main() {
    println!("🔓 Challenge 31");
    // launch web server
    let server_config = Config::build(Environment::Development)
        .port(9000)
        .log_level(LoggingLevel::Off)
        .finalize()
        .unwrap();
    thread::spawn(|| {
        rocket::custom(server_config).mount("/", routes![test]).launch();
    });

    // launch timing attack at the server
    thread::sleep(Duration::from_secs(1)); // make sure the server is launched
    let tag = timing_attack().await;
    println!("The tag/signature is: {}", tag);
}

async fn timing_attack() -> String {
    let file = "foo";
    println!("Finding tag of 'foo' via timing attack...");
    let mut sig = [0 as u8; 20];
    for i in 0..20 {
        for byte in 0..=255 {
            sig[i] = byte;
            let now = Instant::now();
            query(&file, &sig).await.unwrap();
            if now.elapsed().as_millis() >= 50 * (i as u128 + 1) {
                println!("the {}th byte is: {:?}", i, byte);
                break;
            }
        }
    }

    // make sure the sig discovered is correct
    let resp = query(&file, &sig).await.unwrap();
    assert!(resp);

    hex::bytes_to_hexstr(&sig)
}

async fn query(file: &str, sig: &[u8]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let uri = format!(
        "http://localhost:9000/test?file={}&signature={}",
        file,
        hex::bytes_to_hexstr(sig)
    );
    let resp = client.get(uri.parse()?).await?;
    if resp.status() == 200 {
        return Ok(true);
    }
    Ok(false)
}
