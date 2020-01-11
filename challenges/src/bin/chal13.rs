#![allow(dead_code)]
use anyhow::{anyhow, Result};
use cipher::{self, Mode};
use rand::{self, RngCore};

fn main() {
    println!("🔓 Challenge 13");
    test_encrypt_decrypt();
    forge_admin();
}

fn test_encrypt_decrypt() {
    let mut key = vec![0 as u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let p = Profile::new("alex@gmail.com");
    let ct = encrypt_profile(&key, &p);
    assert_eq!(decrypt_profile(&key, ct).unwrap(), p);
}

/// # How to forge admin
///
/// Here is the format of the original message to be encrypted
/// email=___&uid=10&role=user
/// <-6-><--><----13----><----
///
/// The exploit is to know the ciphertext blocks of "admin+padding" under an unknown key.
/// And the way to do so is to craft the email address such that the second block is exactly the
/// same as the last (4-th) block (which starts with "admin").
///
/// So the email should be (10 byte || "admin" || "[11 as u8; 11]" || 3 byte)
/// the first 10 bytes are to append to "email" to the first block
/// the `[11 as u8; 11]` is the ECB padding to the last block
/// the last 3 byte is to prepend to the 3rd block so that the last block starts with "admin"
fn forge_admin() {
    let mut crafted_email = b"self-made.admin".to_vec();
    crafted_email.append(&mut vec![11 as u8; 11]);
    crafted_email.append(&mut b"@io".to_vec());

    // NOTE: supposedly, we should use a private, consistent key, similar to challenge 12
    // but to avoid declaring a new `Key` struct to achieve that, we just hold ourselves accountable
    // and never use this key to decrypt and then forge, but forge by exploiting ECB
    let mut key = vec![0 as u8; 16];
    rand::thread_rng().fill_bytes(&mut key);

    let crafted_ct = encrypt_profile(
        &key,
        &Profile::new(&String::from_utf8(crafted_email).unwrap()),
    );

    // make sure the crafted ciphertext has the right length
    assert_eq!(crafted_ct.len(), 4 * 16);

    // forge a new profile
    let mut forged_ct = crafted_ct.clone();
    forged_ct.truncate(3 * 16);
    forged_ct.extend_from_slice(&crafted_ct[16..32]);

    // Declare a new self-made admin
    println!(
        "Let's welcome the self-made admin: \n 🤴\n{:#?}",
        decrypt_profile(&key, forged_ct).unwrap()
    );
}

fn profile_for(email: &str) -> String {
    let profile = Profile::new(email);
    profile.to_query_str()
}

fn encrypt_profile(key: &[u8], profile: &Profile) -> Vec<u8> {
    let ecb_cipher = cipher::new(Mode::ECB, Some(&[0 as u8; 16]));
    ecb_cipher.encrypt(&key, &profile.to_query_str().as_bytes())
}

fn decrypt_profile(key: &[u8], ct: Vec<u8>) -> Result<Profile> {
    let ecb_cipher = cipher::new(Mode::ECB, Some(&[0 as u8; 16]));
    let profile = ecb_cipher.decrypt(&key, &ct);
    Profile::from_query_str(&String::from_utf8(profile).unwrap())
}

#[derive(Debug, PartialEq)]
struct EmailAddr(String);
impl EmailAddr {
    pub fn new(s: &str) -> Result<EmailAddr> {
        if s.contains("&") || s.contains("=") {
            return Err(anyhow!(
                "Invalid email address, should not contain metacharacter like & or ="
            ));
        }
        Ok(EmailAddr(String::from(s)))
    }
}

#[derive(Debug, PartialEq)]
struct Profile {
    email: EmailAddr,
    uid: u32,
    role: String,
}

impl Profile {
    pub fn new(email: &str) -> Profile {
        Profile {
            email: EmailAddr::new(email).unwrap(),
            uid: 10,
            role: String::from("user"),
        }
    }

    // equivalent to the parser function required
    pub fn from_query_str(s: &str) -> Result<Profile> {
        let mut email = EmailAddr::new("").unwrap();
        let mut uid = 0;
        let mut role = String::new();

        // verify that number of & and = are correct
        if s.matches("&").count() + 1 != s.matches("=").count() {
            return Err(anyhow!("Invalid query string, extra = or &"));
        }

        let kv_pairs: Vec<&str> = s.split("&").collect();
        for pair in kv_pairs.iter() {
            let key_val: Vec<_> = pair.split("=").collect();
            match key_val[0] {
                "email" => email = EmailAddr::new(key_val[1]).unwrap(),
                "uid" => uid = key_val[1].parse::<u32>().unwrap(),
                "role" => role = String::from(key_val[1]),
                _ => return Err(anyhow!("Extra field in query string")),
            };
        }

        Ok(Profile { email, uid, role })
    }

    fn to_query_str(&self) -> String {
        String::from(format!(
            "email={}&uid={}&role={}",
            self.email.0, self.uid, self.role
        ))
    }
}
