#![allow(clippy::many_single_char_names)]
use super::{mod_inv, random_nonzero_bytes};
use lazy_static::lazy_static;
use num::{bigint::RandBigInt, BigUint, Integer, One};
use rand::seq::SliceRandom;
use regex::bytes::Regex;
use ring::io::der;
use sha1::{Digest, Sha1};

// generating prime is hard, borrow existing prime from @rozbb
// https://github.com/rozbb/mcc-rust/blob/master/set5/c39.rs
static PRIMES: &[&[u8]] = &[
    b"DFD18B60EA79CF96D466E1EACDFA299A2338BD90C3BB6A53E7F2463ABEDF504CB860CF6EC33606F6B1CAD9D775987B\
    DFB2FDF89E57903E74686DE7253436AB4ECFFDA637F5E01C7850154B35E790ABF5005E9C703DFD8A314777D0D1B5D9\
    74DFD242088B612866AEA7DE04A6D5AEE6CFEADD8412957A74877C12F35C02A9D0A3568E843BD1BB21CE046A3D0878\
    7D2D30E63EB384B3DA29F6D4E2F98230F90A29B214226A384B291676C37E5AE49ACA7D4F0B34A4EED629591653BCC6\
    1FF5FC480077597E17BCF56284FA9BC0BCEF319581B198DC325E5C57AF46B4E0BB95E5BF4E6454662F293C23D74C79\
    838EABBC35C1DDE082541CD30576E21D9EEF7F9A53",
    b"D5F52B872939D9D5131BA7B1BB4685E0AA75430263A5CAF3B86DA5DCC8BA9FCA0E8E5A37D52FD06A893BA2402C8D0B\
    8D3D56CA262BA0A22B4947C87BACF8E36444AD0DA1F180E144BD2CC18D86B14A79FC22643C6D8A9841891994FA2188\
    26ECAE415F2F11ED2CFC9FB3435F43188C5A65B58A765B34DCA13FEBB41EB51FE07C896923644B401A19E885D1CB35\
    2C053BD5DA4535FFEA96925EEB51D247E81515F96BA4C5A50CA8C18698A42DCEF0BFE2674750BCC1204287C834C613\
    CFC94A614B8424CE4D73B5B1B6968B285525AFD24E3ED2488A779751AE154990548E97D8128808D0966C92356DE297\
    21CAE6B8127F6AA50C42A58E69812BDFCAC4829A61",
    b"CF4F551354400B8FFCA1F3350C21CBF21602352E11B67C85BAADB077662AE5EB2ABC96F95CFA3028BAF65F22676B05\
    26B2EE678D54D8170F193D1FA362765641AE647DC65ECE34F18AC7DCCACDC0E6CE92BAFED0940FCA5E8CA54C01966A\
    A2FD01D945C99DDE8C63147E086965A598ADA811C56199CF6AD4779F7B13D884DCA32401ECC24216435E233D8C6CD1\
    6795A5025BB84811DA9E0B9F223F91815CACBB1D2A1DEDE7B545B85BA1522D9F338798DFDCD39D9185708DAC9FB9E0\
    1241C9C5A2AFA6AF36CC5F363D57DF0931C54DB84950FBB092BFB96575228E14B8E4A1D48E0EF5596AF6BFF53BC469\
    7BF72528D6E0F7EDEB3F29CF1A9A2CFD31C8C64FBB",
    b"C8242CCC6AE6870D7584068E00D471C2EFF56263AD6FD0817A366683E8C711A92044C051859A087EE837593B45D0BD\
    C9D9530B9C234A43BBB8764C6C6D94DB66835B66DA5D264E0FC82CB50FDE47F1D5FEE99BE7BCC83BCD6FCF39369562\
    04405C4C40954609A1057AFDC4D29DE11F101B8FA9D9F8B4020930337DF221C679ED29B16E5790F56E0C33C3DA9F47\
    61A07F48172A35D4AC3E373276F327AEB985527342717D4A6C39CA79CEBE948CF78C4E5CAA7CE9362E7F2421DCDC2C\
    541BE6E8917D972EAC8C9F89076314C1810DAC249FE24B482A795BCF16BD9A85BD43E28B4F3C4A665DC1FA74EEC4FF\
    764D1B3F891903D78457E44AEDBD751E98D3AF37BB",
    b"C0BA20F8BB403C8A979117661A6918E1DCD7FBDD553AA64D7DC7FBDDCDE8E71D70556D28C9FEECD688E2B425C406F5\
    146158BDB702540F32E528BC9A055F81279897A4406A52934584FD9C8147E7A9017C891C311FF30F249A165A695DB5\
    81805A193D17019770DBE04560538103933A10CE3C56D581F3F01417B3ECB6CF39CD760311E203A161721C549F805B\
    C9049580193E784D4F2E03EF70F93B2FE42BCD21DA7EB0CD899D2EDE3C4433A20EE2320452AF2FD555F569EDC18071\
    58014C24DB0ABDD8DD99D4331A034E763D509082F638C55E11EDBEFD5CCDC1EBFEDE1D89F11076E568A1B2E2D818DF\
    DBBC8E51EE43576DE07953AC482FFDDA564D2313DF",
    b"DA28B746E14034178863281D9600E8B0A18FB7515F274BCDD3E322E1893CB81FA2085580CDDB655C53992ED9344DD7\
    F426B9D778AF9A2647500030AF51CBA216F0711B29BD19B88CACC7832F713E0A79911EC3A729EBF1262BDAF88CB5A9\
    D386D40E8F45797B9A8D598FD4DDC9EBEE6C4CD6595E93D6DDAF9734743A3B503873C55BEA5DF1AD8C1DCD901C6BBD\
    0453DDFCB9EF58A5D78E25C31D896C32403356C1E80C170F1FADFF61FAA93E40776E2943143D96B5DDDAC902F58E89\
    995B3218D2847147B14E3CBA60E4E8AFDC3A070FFDEE35C4BACA7169E49240A864CCB2C34FA132008B0226D6B23F51\
    1DB2F3B5BB71E7DD703BC4C8495D5B2D0C62D588BB",
    b"DF7C942CDC04E43E3FAA617C5A5168F3A5D87A4BFA31E5D477524C8CDC39A4CCCFA17EB30BE69196894942154F3598\
    B547BD77A85E28D5BD89FCDAE0D3C73A6A620A91C0B3F769C6B3EB61DB5EBCE90B49916409E8255B7FDE9C4BE5BDBD\
    2B04F4A00B6B41FFE0F1C870F09C385772595B7DA8E88DAC9B9DA1F7780FB169454CB70693B5600E42172E0CA8B42D\
    7F512EC488959041A5C5240E7582463DB0DD0B1A58CB0A04BF4720EB201E63D8904FA0D5C342B285ED2F210CAE4FD6\
    C2FA7EB34206E92B870EF082F5D2C0CDCB455200ACBF3A7CBFD5C48BA6FA3895E6DD885CBEB60E0949438A0C11CBA6\
    506589DF766836F62569A7D5ABB897BE640C887BBF",
    b"CBFACFC286B66FE7C29383F49C692BD70EA600C126746E233F62A1955E5AA6BD52FF1BE2BB5F89A0900A7EC4C521A1\
    230F797AE1DAD150CF66FFD58564DA542EEAD2FC27F0030A6D59DB5BDB87B343B8829B558021CA27DF210F1C5CE45C\
    7E1ECD54B4D3D4D58AE874C463D9BCB689E90A299ECC40C51FC6220AD75F72877D6C34AC441AE6CD2EB5539F6B93D7\
    3FF4A46079820470BEE9A06867F271E882DFCFA5552779925BF1A0D45C2B01AE1627ECD60546DE98366D4396D886B0\
    219DC576FF617EE55B41A9248F0FC00921DC2773595A582755E4376BF69BE5A62511FB787FD8E44A8DC71113EC5BCF\
    8F8A0CC02201B5CDBC61F86A4B0F9E2DD0685903DB",
    b"F2FCFE33B211E29AAF24FDC54701C80F0ADDF84AA2A743A479EEA27CD0DCED34DFBF3F9D76FC9F3675DAFC2E34167C\
    C03EAE362E107D56805A7E5622A4C7447B2A736E1867DEC0FE5B5D3B847F1C6652BF3CFAAA737B173EB643737AF601\
    9399CE931CCEC664A32111A589F36EEE21038F631D1ADC900565F9AA03D97210FE090F36F1885347AC49588F46CFAE\
    0098C65BDDD31FF03B9B509E23E51E6E5E58B26AF32778C62A1D2B0E1FE81F9612D0BBE1BA7510E867FD53651D7D2B\
    89A84EE636025B307C032735463F695F5D7396601D050D00B572DEA1C339E04B93AFFED17F9EBEA45C45AFCAFB2AD8\
    129381A7831204BABF5E9D077EE570A1F4C8F67B45",
    b"CF4514D24E25116BA019E36F7CC5181D5A34841F862B2A8AAC6E518AB96A744231B756865AC591036CB8A6B77E4523\
    05B532F779D53875DDED9C8949CE88C111F42C38FB34F235B90ACAF3F23B8CFA9A14331626C17C61493A8E5ED3165B\
    F252D103A1BB341B6AF5455BFAF7559D2D977A5F502DA3393055AD49E7421FFD4F9A06E36AE145F3568EE462ED31C6\
    055674C6793890A812DB673F70F51E6245D149810B02D44178C94B8CC2B6A78DC6A757F0F52A5A19F108441C9CFED9\
    72CE82BADA57B6AAC9AE3EF7C48BAF1C36BE9FF7E69DC293E88D20654136BFD5F474B4E1BC7950CC4DB877E918394E\
    E081C500DCB04D59ADEC5BF7FBF942D43CFCBEB5E1",
    b"DE9DC0DF36A8562AF44D4B644CFE951B4C7B9222D7995153C82C3B4ADA62BC4D0AEDD964609EF8FD559FC2D8C1ADAA\
    DB6142EFDF6CBD46E389CD170C0FED911C3E83F956625CC3535D99C989D97BD7DD1D831F18FF6FFDA6345910AAE5DE\
    AFDFEB1B40F4774DFCF5035FAAECEE0628140E432C9748D6499B80977F227F31B07B12D7EF888E83A25CEA7DAEF447\
    93ABD92187F7B6C563DB640C0FDB9BF5BA74A86953BE8F0EC2BDD67B428E868A477B4CC7A5C96A27C618F65DCD7B89\
    7006818571D3D083960B34CEB33313F364988FA3EA29DD806E0EBB843CC3BA095E756982D6978DD38080C0402CD19F\
    268782B15A02841A82AB3C4346D86C7A206303E269",
];

// credit: https://github.com/briansmith/ring/blob/master/src/rsa/padding.rs#L171-L190
macro_rules! pkcs1_digestinfo_prefix {
    ( $name:ident, $digest_len:expr, $digest_oid_len:expr,
      [ $( $digest_oid:expr ),* ] ) => {
        pub static $name: [u8; 2 + 8 + $digest_oid_len] = [
            der::Tag::Sequence as u8, 8 + $digest_oid_len + $digest_len,
                der::Tag::Sequence as u8, 2 + $digest_oid_len + 2,
                    der::Tag::OID as u8, $digest_oid_len, $( $digest_oid ),*,
                    der::Tag::Null as u8, 0,
                der::Tag::OctetString as u8, $digest_len,
        ];
    }
}

pkcs1_digestinfo_prefix!(
    SHA1_PKCS1_DIGESTINFO_PREFIX,
    20,
    5,
    [0x2b, 0x0e, 0x03, 0x02, 0x1a]
);

fn rand_two_primes() -> (BigUint, BigUint) {
    let mut rng = rand::thread_rng();
    let primes: Vec<BigUint> = PRIMES.choose_multiple(&mut rng, 2)
        .map(|&s| BigUint::parse_bytes(&s.to_vec(), 16).unwrap())
        .collect();
    (primes[0].to_owned(), primes[1].to_owned())
}

#[derive(Debug, Clone)]
pub struct RsaKeyPair {
    pub pubKey: RsaPubKey,
    pub priKey: RsaPriKey,
}

#[derive(Debug, Clone)]
pub struct RsaPubKey {
    pub e: BigUint,
    pub n: BigUint,
}

#[derive(Debug, Clone)]
pub struct RsaPriKey {
    d: BigUint,
    n: BigUint,
}

impl Default for RsaKeyPair {
    fn default() -> Self {
        let (p, q) = rand_two_primes();
        let n = &p * &q;
        let phi_n = (p - BigUint::one()) * (q - BigUint::one());

        let e = BigUint::parse_bytes(b"3", 10).unwrap(); // PubKey
        let d = mod_inv(&e, &phi_n).expect("should be able to derive private key");

        RsaKeyPair {
            pubKey: RsaPubKey { e, n: n.clone() },
            priKey: RsaPriKey { d, n },
        }
    }
}

impl RsaKeyPair {
    /// generate certain number of key pairs
    /// currently only support <= 4 pairs
    pub fn gen(pairs: usize) -> Vec<Self> {
        let mut key_pairs = vec![];
        for i in 0..pairs {
            let p = BigUint::parse_bytes(PRIMES[2 * i], 16).unwrap();
            let q = BigUint::parse_bytes(PRIMES[2 * i + 1], 16).unwrap();
            let n = &p * &q;
            let phi_n = (p - BigUint::one()) * (q - BigUint::one());

            let e = BigUint::parse_bytes(b"3", 10).unwrap(); // PubKey
            let d = mod_inv(&e, &phi_n).expect("should be able to derive private key");

            key_pairs.push(RsaKeyPair {
                pubKey: RsaPubKey { e, n: n.clone() },
                priKey: RsaPriKey { d, n },
            });
        }
        key_pairs
    }

    /// this is determinsitic, one time use only
    pub fn new_1024_rsa() -> Self {
        // openssl prime -generate -bits 64 -hex
        // parameters for faster testing
        // let p = BigUint::parse_bytes(b"C2F25585EC182537", 16).unwrap();
        // let q = BigUint::parse_bytes(b"DBCF88A5367DC841", 16).unwrap();

        let q = BigUint::parse_bytes(
            b"D59A80647781445E695BD1BF901F472BE01302929A89FF91B579777C4F61DA79\
              EE05C556D0F70985D4A018FE03B196DB3B2C70B7647D28BE97971552FC8837CB",
            16,
        )
        .unwrap();
        let p = BigUint::parse_bytes(
            b"F91D45F2953C94822066AD81044407A5B2B5A8EA6E16E0376116AEF16C1DCC39\
              AF5C13A75A776394C35C86443A8ECD569C4CE31913E9E05A38ACA677C079DD9D",
            16,
        )
        .unwrap();

        Self::rsa_core(&p, &q)
    }

    /// deterministic keygen, one time use only
    pub fn new_256_rsa() -> Self {
        // p, q are 128 bits
        let q = BigUint::parse_bytes(b"DFD08A944B0DDB457C1E164D88FA8D73", 16).unwrap();
        let p = BigUint::parse_bytes(b"E03069878F0B0F2E7A259665DE528DB5", 16).unwrap();

        Self::rsa_core(&p, &q)
    }

    fn rsa_core(p: &BigUint, q: &BigUint) -> Self {
        let n = p * q;
        let phi_n = (p - BigUint::one()) * (q - BigUint::one());

        let mut rng = rand::thread_rng();
        let mut e = BigUint::one();
        let mut d = None;
        while d.is_none() {
            e = rng.gen_biguint_below(&phi_n);
            d = mod_inv(&e, &phi_n);
        }

        RsaKeyPair {
            pubKey: RsaPubKey { e, n: n.clone() },
            priKey: RsaPriKey { d: d.unwrap(), n },
        }
    }
}

impl RsaPubKey {
    /// RSA encryption
    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }

    /// returns the PKCS1.5 padded messgae
    pub fn pkcs_pad(&self, msg: &[u8]) -> BigUint {
        let n_bytes: usize = self.n.bits() as usize / 8;
        if msg.len() > n_bytes - 11 {
            panic!("Too long of a message than our naive code can support");
        }
        let padding_bytes = random_nonzero_bytes((n_bytes - 3 - msg.len()) as u32);
        let padded_msg = [
            b"\x00\x02".to_vec(),
            padding_bytes,
            b"\x00".to_vec(),
            msg.to_vec(),
        ]
        .concat();
        BigUint::from_bytes_be(&padded_msg)
    }

    /// unpad the PKCS1.5 padding on RSA Signature of the format: 00 01 ff ... ff 00 ASN.1 HASH
    /// this unpad function returns the "HASH" payload
    fn unpad_sig(sig: &[u8]) -> Option<Vec<u8>> {
        lazy_static! {
            // (?-u) is flag to disable ASCII(valid UTF-8) charater restrait by default
            // \xff{8,}? is at least 8 bytes of `\xff` as the spec
            // \x00 is the signal for upcoming `ASN.1 HASH` which is captured in `asn` and `payload`
            static ref RE_SIG_PAD: Regex = Regex::new(r"(?s-u)^\x00\x01\xFF{8,}?\x00(?P<asn>.{15})(?P<payload>.{20})").unwrap();
        }
        let cap = RE_SIG_PAD.captures(&sig);
        match cap {
            None => None,
            Some(c) => {
                if c.name("asn").unwrap().as_bytes() != SHA1_PKCS1_DIGESTINFO_PREFIX {
                    panic!("wrong ASN.1 encoding, internal error, only support SHA1_PKCS_1 for now");
                    // should never reach here
                }
                Some(c.name("payload").unwrap().as_bytes().to_vec())
            }
        }
    }

    /// broken RSA signature verification found in some PKCS#1 v1.5 implementations
    pub fn broken_sig_verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let sig_pt = self.encrypt(&BigUint::from_bytes_be(&sig)); // signature plaintext
        let sig_pt = [b"\x00".to_vec(), sig_pt.to_bytes_be()].concat(); // put back the \x00 chunk off during conversion
        match Self::unpad_sig(&sig_pt) {
            None => false,
            Some(payload) => {
                let mut h = Sha1::default();
                h.input(&msg);
                h.result().to_vec() == payload
            }
        }
    }
}

impl RsaPriKey {
    /// decrypt RSA ciphertext
    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        c.modpow(&self.d, &self.n)
    }

    /// an oracle that takes a ciphertext and returns whether the decryped plaintext is even
    pub fn parity(&self, c: &BigUint) -> bool {
        self.decrypt(&c).is_even()
    }

    // Bleichenbacher 98 oracle which returns true if the decrypted bytes start with 00 02
    // which is the PKCS1.5 padding format
    pub fn bb_oracle(&self, c: &BigUint) -> bool {
        let pt = &self.decrypt(&c).to_bytes_be();
        // since BigUint when converting to bytes will ignore any zero bytes in front,
        // to verify the plaintext starts with 00 02, equivalently means that it starts with 02
        // and with a byte length one less than that of n
        pt[0] == 2 && pt.len() == self.n.bits() as usize / 8 - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_encrytpion() {
        let key_pair = RsaKeyPair::default();
        let m = BigUint::parse_bytes(b"42", 10).unwrap();
        let ct = key_pair.pubKey.encrypt(&m);
        assert_eq!(key_pair.priKey.decrypt(&ct), m);
    }

    #[test]
    fn pkcs1_5_sig_unpad() {
        let sig1 = [
            vec![0, 1, 255, 255, 255, 255, 255, 255, 255, 255, 0],
            SHA1_PKCS1_DIGESTINFO_PREFIX.to_vec(),
            vec![100 as u8; 20],
        ]
        .concat();
        let sig2 = [
            vec![0, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0],
            SHA1_PKCS1_DIGESTINFO_PREFIX.to_vec(),
            vec![200 as u8; 30],
        ]
        .concat();
        let sig3 = vec![0, 1, 255, 255, 255, 255, 255, 255, 255, 1];

        assert_eq!(RsaPubKey::unpad_sig(&sig1).unwrap(), vec![100 as u8; 20]);
        assert_eq!(RsaPubKey::unpad_sig(&sig2).unwrap(), vec![200 as u8; 20]);
        assert_eq!(RsaPubKey::unpad_sig(&sig3), None);
    }
}
