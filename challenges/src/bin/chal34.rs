use cipher::{self, Mode};
use dh::{mod_p::Dh, DH};
use num::bigint::BigUint;
use sha1::{Digest, Sha1};

fn main() {
    println!("🔓 Challenge 34");
    normal_protocol();
    mitm();
}

struct Person {
    dh: Dh,
    sk: BigUint,
    pub pk: BigUint,
}

impl Person {
    pub fn new() -> Person {
        let dh = Dh::new();
        let (sk, pk) = dh.key_gen();
        Person { dh, sk, pk }
    }

    pub fn gen_session_key(&self, pk: &BigUint) -> BigUint {
        self.dh.kex(&self.sk, &pk)
    }
}

fn normal_protocol() {
    println!("Starting normal protocol...");
    let alice = Person::new();
    let bob = Person::new();
    let alice_session_key = alice.gen_session_key(&bob.pk);
    let bob_session_key = bob.gen_session_key(&alice.pk);

    let msg = b"secert msg from A to B".to_vec();
    let alice_ct = encrypt(&alice_session_key, &msg);
    let bob_ct = encrypt(&bob_session_key, &decrypt(&bob_session_key, &alice_ct));

    assert_eq!(decrypt(&alice_session_key, &bob_ct), msg);
    println!("Success!");
}

fn mitm() {
    println!("Simulating Man-in-the-Middle Attack...");
    let alice = Person::new();
    let bob = Person::new();
    let eve = Person::new();
    let alice_eve_key = eve.gen_session_key(&alice.pk);
    let eve_bob_key = eve.gen_session_key(&bob.pk);

    // Alice sending message to Eve
    let msg_alice = b"msg intended from Alice to Bob".to_vec();
    let alice_ct = encrypt(&alice_eve_key, &msg_alice);

    // Eve decrypt it and forward to Bob
    let eve_ct = encrypt(&eve_bob_key, &decrypt(&alice_eve_key, &alice_ct));

    // Bob sending message to Eve
    let msg_bob = decrypt(&eve_bob_key, &eve_ct);
    let bob_ct = encrypt(&eve_bob_key, &msg_bob);

    // Eve decrypt it and forward to Alice
    let eve_ct = encrypt(&alice_eve_key, &decrypt(&eve_bob_key, &bob_ct));

    // finally, alice verifies the msg (and thought "everything is fine")
    assert_eq!(decrypt(&alice_eve_key, &eve_ct), msg_alice);
    assert_eq!(msg_alice, msg_bob);
    println!("MiTM Succeed!");
}

fn encrypt(session_key: &BigUint, msg: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.input(session_key.to_bytes_le());
    let enc_key = &h.result().to_vec()[..16];

    let cbc_cipher = cipher::new(Mode::CBC);
    cbc_cipher.encrypt(&enc_key, &msg)
}
fn decrypt(session_key: &BigUint, ct: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.input(session_key.to_bytes_le());
    let enc_key = &h.result().to_vec()[..16];

    let cbc_cipher = cipher::new(Mode::CBC);
    cbc_cipher.decrypt(&enc_key, &ct)
}
