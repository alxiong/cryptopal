use challenges::chal49::*;
use challenges::random_bytes;

fn main() {
    println!("🔓 Challenge 49");
    variable_iv_attack();
    extension_attack();
}

// attack idea: with a previously signed (msg, mac) using iv of zero,
// then a forged message whose iv is the XORed difference between the msg and the
// forged_msg, then the mac is still valid, thus a successful forgery
fn variable_iv_attack() {
    println!("\nMAC forgery with attacker-controlled iv ...");
    let msg = b"from=12345&to=attacker&amount=1000000".to_vec();
    let key = random_bytes(16);
    let client = Client::new("alice", &key);
    let server = Server::new(&key);
    let mac = client.sign(&msg).unwrap();

    let forge_msg = b"from=alice&to=attacker&amount=1000000".to_vec();
    let iv = xor::xor(&msg.split_at(16).0, &forge_msg.split_at(16).0).unwrap();
    if server.verify(&forge_msg, &iv, &mac) {
        println!("Successfully forged an evil transfer!\n");
    }
}

// attack idea:
// tag1 = CBC-MAC(msg1 || pad1)
// tag2 = CBC-MAC(msg1 || pad1 || msg2 || pad2)
// tag2' = CBC-MAC(tag1 ^ (msg2 || pad2))
// tag2 == tag'
fn extension_attack() {
    println!("\nMAC forgery with fixed iv using extension attack ...");
    let msg = b"from=alice&tx_list=bob:10;charlie:32;david:9".to_vec();
    let key = random_bytes(16);
    let client = Client::new("alice", &key);
    let server = Server::new(&key);
    let mac = client.sign(&msg).unwrap();

    let padded_msg = cbc_pad(&msg);
    let evil_tx = b";evil:1000000".to_vec();
    let padded_evil_tx = cbc_pad(&evil_tx);

    let forged_msg = [padded_msg, padded_evil_tx.clone()].concat();
    let forged_mac = client.sign(&xor::xor(&padded_evil_tx, &mac).unwrap()).unwrap();

    if server.fixed_iv_verify(&forged_msg, &forged_mac) {
        println!("Successfully append an evil transfer!\n");
    }
}

fn cbc_pad(msg: &[u8]) -> Vec<u8> {
    let mut padded = msg.to_vec();
    if msg.len() % 16 == 0 {
        padded.append(&mut vec![16 as u8; 16]);
    } else {
        let padding_len = 16 - msg.len() % 16;
        padded.append(&mut vec![padding_len as u8; padding_len as usize]);
    }
    padded
}
