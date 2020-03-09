use challenges::{
    chal43::{dsa_leaky_k_attack, hash_msg_to_hexstr, is_dsa_key_pair},
    chal43::{DsaKeyPair, DsaPubKey, DsaPublicParam, DsaSignature},
    random_bytes,
};
use num::{BigUint, FromPrimitive};
use std::process;

fn main() {
    println!("🔓 Challenge 43");

    println!("Leaky k DSA signing attack ... (may take a few sec)");
    let total_crack = 100;
    let mut success_crack = 0;
    for _ in 0..total_crack {
        let dsa = DsaKeyPair::key_gen();
        let pk = dsa.get_pub_key();
        let msg = random_bytes(30); // arbitarily chosen message length

        let (k, sig) = dsa.leaky_sign(&msg);
        let guess_key = dsa_leaky_k_attack(&pk, &msg, &k, &sig);

        if is_dsa_key_pair(&pk, &guess_key) {
            success_crack += 1;
        }
    }
    println!(
        "Cracked the private key {} out of {} times",
        success_crack, total_crack
    );

    println!("\nRealisitc attack on DSA signature with low entropy k ... (took me ~7min on my laptop)");
    let pk = DsaPubKey {
        pub_param: DsaPublicParam::default(),
        pub_key: BigUint::parse_bytes(
            b"84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2\
              955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2\
              e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779\
              191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17",
            16,
        )
        .unwrap(),
    };

    let msg = b"For those that envy a MC it can be hazardous to your health\n\
                    So be friendly, a matter of life and death, just like a etch-a-sketch\n"
        .to_vec();

    let sig = DsaSignature {
        r: BigUint::parse_bytes(b"548099063082341131477253921760299949438196259240", 10).unwrap(),
        s: BigUint::parse_bytes(b"857042759984254168557880549501802188789837994940", 10).unwrap(),
    };

    // given that k is between 0 and 2^16 due to poor entropy, we can crack it.
    for _k in 1..65537 {
        let k = BigUint::from_u64(_k).unwrap();
        let guess = dsa_leaky_k_attack(&pk, &msg, &k, &sig);
        if is_dsa_key_pair(&pk, &guess)
            && hash_msg_to_hexstr(&guess.to_str_radix(16).as_bytes())
                == String::from("0954edd5e0afe5542a4adf012611a91912a3ec16")
        {
            println!("Cracked your private key: {} !!", &guess.to_str_radix(16));
            process::exit(0);
        }
    }
    panic!("Failed to crack the private key.");
}
