use super::random_bytes;
use bytes::Buf;
use dh::{mod_p::Dh, DH};
use encoding::hex;
use hmac::{Hmac, Mac};
use hyper::{Body, client::Client, Method, Request, Uri};
use num::{bigint::RandBigInt, BigUint};
use rocket::{self, get, post, routes};
use rocket::{
    config::{Config, Environment, LoggingLevel},
    http::Status,
    State,
};
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;

const EMAIL: &str = "outlook@gmail.com";
pub const PASSWORD: &str = "password_is_username";

#[derive(Debug)]
struct ServerState {
    dh: Dh,
    salt: Vec<u8>,
    b: BigUint,
    K: Vec<u8>,
    database: HashMap<String, BigUint>,
}

impl ServerState {
    pub fn new() -> ServerState {
        ServerState {
            dh: Dh::new(),
            salt: vec![],
            b: BigUint::default(),
            K: vec![],
            database: HashMap::new(),
        }
    }
    /// initialize
    pub fn init(&mut self) {
        self.dh = Dh::new();
        self.salt = random_bytes(32); // 32 is arbitary, can be any number

        let mut hasher = Sha256::new();
        hasher.input([self.salt.clone(), PASSWORD.as_bytes().to_vec()].concat());
        let x = bytes_to_biguint(&hasher.result().to_vec());

        self.database.insert(EMAIL.to_string(), self.dh.exp(&x));
    }
    /// input: A; returns (salt, B)
    pub fn kex(&mut self, email: &str, A: &BigUint) -> (Vec<u8>, BigUint, BigUint) {
        let v = self.database.get(&email.to_string()).unwrap(); // more graceful way would be return a Result

        // randomly generate ephermal key pair
        // B =  g^b mod p
        let (b, B) = self.dh.key_gen();
        self.b = b;

        // u is a random 128 bit
        let mut rng = rand::thread_rng();
        let u = rng.gen_biguint(128);

        let S = (A * v.modpow(&u, &self.dh.p)).modpow(&self.b, &self.dh.p);

        let mut hasher = Sha256::new();
        hasher.input(S.to_bytes_le());
        self.K = hasher.result().to_vec();

        (self.salt.clone(), B, u)
    }
    /// verify Hmac upon key exchange
    pub fn verify(&self, tag: &[u8]) -> bool {
        let mut hmac_sha256 = Hmac::<Sha256>::new_varkey(&self.K).expect("HMAC can take varkey");
        hmac_sha256.input(&self.salt);
        if hmac_sha256.verify(&tag).is_ok() {
            return true;
        }
        false
    }
    /// reset state
    pub fn reset(&mut self) {
        self.dh = Dh::new();
        self.salt = vec![];
        self.b = BigUint::default();
        self.K = vec![];
        self.database = HashMap::new();
    }
}

struct ServerStateWrapper {
    ss: RwLock<ServerState>,
}

#[get("/init")]
fn init(state: State<ServerStateWrapper>) {
    state.inner().ss.write().unwrap().init();
}

#[derive(Serialize, Deserialize)]
struct KexInput {
    email: String,
    A: String, // A is BigUint.to_str_radix(16)
}

#[derive(Serialize, Deserialize, Debug)]
struct KexOutput {
    salt: Vec<u8>,
    B: String, // B is BigUint.to_str_radix(16)
    u: String,
}

#[post("/kex", format = "json", data = "<input>")]
fn kex(input: Json<KexInput>, state: State<ServerStateWrapper>) -> Json<KexOutput> {
    let email = input.0.email;
    let A = BigUint::parse_bytes(&input.0.A.as_bytes(), 16).unwrap();
    let (salt, B, u) = state.inner().ss.write().unwrap().kex(&email, &A);
    let B = B.to_str_radix(16);
    let u = u.to_str_radix(16);
    Json(KexOutput { salt, B, u })
}

#[get("/verify?<tag>")]
fn verify(tag: String, state: State<ServerStateWrapper>) -> Status {
    let tag = hex::hexstr_to_bytes(&tag).unwrap();
    if state.inner().ss.read().unwrap().verify(&tag) {
        return Status::Ok;
    }
    Status::InternalServerError
}

#[get("/reset")]
fn reset(state: State<ServerStateWrapper>) -> Status {
    state.inner().ss.write().unwrap().reset();
    Status::Ok
}

pub fn bytes_to_biguint(b: &[u8]) -> BigUint {
    BigUint::from_bytes_le(&b)
}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub async fn query_init() -> Result<()> {
    let client = Client::new();
    client.get(Uri::from_static("http://localhost:9000/init")).await?;
    Ok(())
}

pub async fn query_kex(email: &str, A: &BigUint) -> Result<(Vec<u8>, BigUint, BigUint)> {
    let client = Client::new();
    let req = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:9000/kex")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "email": email,
                "A": A.to_str_radix(16),
            })
            .to_string(),
        ))?;
    let resp = client.request(req).await?;
    // asynchronously aggregate the chunks of the body
    let body = hyper::body::aggregate(resp).await?;
    let server_output: KexOutput = serde_json::from_reader(body.reader())?;
    Ok((
        server_output.salt,
        BigUint::parse_bytes(&server_output.B.as_bytes(), 16).unwrap(),
        BigUint::parse_bytes(&server_output.u.as_bytes(), 16).unwrap(),
    ))
}

pub async fn query_verify(tag: &[u8]) -> Result<bool> {
    let client = Client::new();
    let uri = format!("http://localhost:9000/verify?tag={}", hex::bytes_to_hexstr(&tag));
    let resp = client.get(uri.parse()?).await?;
    if resp.status() == 200 {
        return Ok(true);
    }
    Ok(false)
}

pub async fn query_reset() -> Result<bool> {
    let client = Client::new();
    let uri = "http://localhost:9000/reset".parse()?;
    let resp = client.get(uri).await?;
    if resp.status() == 200 {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[derive(Debug, Default)]
pub struct ClientState {
    dh: Dh,
    a: BigUint,
    A: BigUint,
    K: Vec<u8>,
}

impl ClientState {
    pub fn new() -> ClientState {
        ClientState {
            dh: Dh::new(),
            a: BigUint::default(),
            A: BigUint::default(),
            K: vec![],
        }
    }
    /// initiate key exchange by outputing (Email, A = g ^ a)
    pub fn init(&mut self) -> (String, BigUint) {
        let (a, A) = self.dh.key_gen();
        self.a = a;
        self.A = A.clone();
        (EMAIL.to_string(), A)
    }
    /// perform key exchange, return HMAC tag for verification
    pub fn kex(&mut self, salt: &[u8], B: &BigUint, u: &BigUint) -> Vec<u8> {
        // get x = Sha256(salt || password)
        let mut hasher = Sha256::new();
        hasher.input([salt.to_owned(), PASSWORD.as_bytes().to_vec()].concat());
        let x = bytes_to_biguint(&hasher.result().to_vec());

        // derive shared session key
        let S = B.modpow(&(&self.a + u * &x), &self.dh.p);

        let mut hasher = Sha256::new();
        hasher.input(S.to_bytes_le());
        self.K = hasher.result().to_vec();

        // get hmac tag for verification of the ephermal shared key
        let mut hmac_sha256 = Hmac::<Sha256>::new_varkey(&self.K).expect("HMAC can take varkey");
        hmac_sha256.input(&salt);
        hmac_sha256.result().code().to_vec()
    }
}

pub fn launch_server() {
    let server_config = Config::build(Environment::Development)
        .port(9000)
        .log_level(LoggingLevel::Normal)
        .finalize()
        .unwrap();
    rocket::custom(server_config)
        .mount("/", routes![init, kex, verify, reset])
        .manage(ServerStateWrapper {
            ss: RwLock::new(ServerState::new()),
        })
        .launch();
}
