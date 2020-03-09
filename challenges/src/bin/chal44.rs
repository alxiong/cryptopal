use challenges::chal43::{dsa_leaky_k_attack, hash_msg_to_hexstr, DsaPublicParam, DsaSignature};
use challenges::{mod_inv, mod_sub};
use num::BigUint;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::process;

fn main() {
    println!("🔓 Challenge 44");

    let msgs = read_data();
    let pub_parm = DsaPublicParam::default();

    // hashmap storing (r, index) where r is part of the signature, index is the index of msgs list
    let mut map: HashMap<String, usize> = HashMap::new();
    for (i, msg) in msgs.iter().enumerate() {
        match map.get(&msg.r) {
            None => {
                map.insert(msg.r.clone(), i);
            }
            Some(&index) => {
                let guess = repeated_nonce_attack(&msg, &msgs[index], &pub_parm.q);
                if is_correct_prikey(&guess) {
                    println!("Successfully extract your private key!");
                    process::exit(0);
                }
            }
        };
    }
}

#[derive(Deserialize, Debug)]
struct DsaMessage {
    msg: String,
    s: String,
    r: String,
    m: String,
}

fn read_data() -> Vec<DsaMessage> {
    let data_str = fs::read_to_string("challenges/data/chal44.json").unwrap();
    serde_json::from_str::<Vec<DsaMessage>>(&data_str).unwrap()
}

// given two signatures signed using the same nounce k, extract and returns the private key
fn repeated_nonce_attack(m1: &DsaMessage, m2: &DsaMessage, q: &BigUint) -> BigUint {
    let m_1 = BigUint::parse_bytes(&m1.m.as_bytes(), 16).unwrap();
    let m_2 = BigUint::parse_bytes(&m2.m.as_bytes(), 16).unwrap();
    let s_1 = BigUint::parse_bytes(&m1.s.as_bytes(), 10).unwrap();
    let s_2 = BigUint::parse_bytes(&m2.s.as_bytes(), 10).unwrap();
    // k = (m1 - m1) * (s1 - s2)^-1 mod q
    let k = (mod_sub(&m_1, &m_2, &q) * mod_inv(&mod_sub(&s_1, &s_2, &q), &q).unwrap()) % q;

    let sig_1 = DsaSignature {
        r: BigUint::parse_bytes(&m1.r.as_bytes(), 10).unwrap(),
        s: s_1,
    };
    dsa_leaky_k_attack(&q, &m1.msg.as_bytes(), &k, &sig_1)
}

fn is_correct_prikey(guess: &BigUint) -> bool {
    hash_msg_to_hexstr(&guess.to_str_radix(16).as_bytes())
        == String::from("ca8f6f7c66fa362d40760d135b763eb8527d3d52")
}
