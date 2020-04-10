use cipher::{cbc::AES_128_CBC, Cipher};
use std::collections::HashMap;

const ZERO_IV: [u8; 16] = *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

pub struct Server {
    key: Vec<u8>,
}

impl Server {
    pub fn new(key: &[u8]) -> Server {
        Server { key: key.to_vec() }
    }
    pub fn verify(&self, msg: &[u8], iv: &[u8], mac: &[u8]) -> bool {
        let cbc_cipher = AES_128_CBC::from_iv(&iv);
        let ct = cbc_cipher.encrypt(&self.key, &msg);
        let tag = ct.rchunks(16).next().unwrap();
        tag == mac
    }
    pub fn fixed_iv_verify(&self, msg: &[u8], mac: &[u8]) -> bool {
        self.verify(&msg, &ZERO_IV, &mac)
    }
}

pub struct Client {
    uid: String,
    key: Vec<u8>,
}

impl Client {
    /// instantiate a new client
    pub fn new(uid: &str, key: &[u8]) -> Client {
        Client {
            uid: uid.to_string(),
            key: key.to_vec(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Option<Vec<u8>> {
        // query string validaity check is commented out, since tx_list is not standard format
        // just ignoring the incoming msg's validity for now
        // let tx = Tx::from_query_str(&msg);
        // if tx.is_none() {
        //     return None;
        // }
        let cbc_cipher = AES_128_CBC::from_iv(&ZERO_IV);
        let ct = cbc_cipher.encrypt(&self.key, &msg);
        Some(ct.rchunks(16).next().unwrap().to_vec())
    }
}

#[derive(Debug, PartialEq)]
struct Tx {
    pub from: String,
    pub to: String,
    pub amount: u32,
}

impl Tx {
    pub fn new(from: &str, to: &str, amount: u32) -> Tx {
        Tx {
            from: from.to_string(),
            to: to.to_string(),
            amount,
        }
    }

    /// parsing a query string into a Tx if valid
    pub fn from_query_str(query: &str) -> Option<Tx> {
        if let Ok(pairs) = serde_urlencoded::from_str::<HashMap<String, String>>(&query) {
            let from = pairs.get("from");
            let to = pairs.get("to");
            let amount = pairs.get("amount");

            if from == None || to == None || amount == None {
                None
            } else {
                Some(Tx {
                    from: from.unwrap().to_owned(),
                    to: to.unwrap().to_owned(),
                    amount: amount.unwrap().parse().unwrap(),
                })
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::random_bytes;
    use super::*;
    #[test]
    fn query_str_parsing() {
        let query = String::from("from=alice&to=bob&amount=99");
        assert_eq!(
            Tx::from_query_str(&query).unwrap(),
            Tx::new(&String::from("alice"), &String::from("bob"), 99)
        );

        let q1 = String::from("to=bob&amount=99");
        assert_eq!(Tx::from_query_str(&q1), None);
    }

    #[test]
    fn server_verify_correctness() {
        let msg = b"from=alice&to=bob&amount=99".to_vec();
        let key = random_bytes(16);
        let client = Client::new("alice", &key);
        let server = Server::new(&key);

        let mac = client.sign(&msg).unwrap();
        assert!(server.verify(&msg, &ZERO_IV, &mac));
    }
}
