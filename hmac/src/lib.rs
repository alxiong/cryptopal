#![no_std]
use core::{cmp::min, fmt};
pub use crypto_mac::Mac;
use crypto_mac::{InvalidKeyLength, MacResult};
use digest::{
    generic_array::sequence::GenericSequence,
    generic_array::{ArrayLength, GenericArray},
    BlockInput, FixedOutput, Input, Reset,
};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// The HMAC using a hash function `D`
pub struct Hmac<D>
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
{
    digest: D,
    i_key_pad: GenericArray<u8, D::BlockSize>,
    opad_digest: D,
}

impl<D> Mac for Hmac<D>
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    type OutputSize = D::OutputSize;
    type KeySize = D::BlockSize;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self::new_varkey(key.as_slice()).unwrap()
    }

    #[inline]
    fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        let mut hmac = Self {
            digest: Default::default(),
            i_key_pad: GenericArray::generate(|_| IPAD),
            opad_digest: Default::default(),
        };
        let mut opad = GenericArray::<u8, D::BlockSize>::generate(|_| OPAD);
        debug_assert!(hmac.i_key_pad.len() == opad.len());

        // The key that Hmac processes must be the same as the block size of the
        // underlying Digest. If the provided key is smaller than that, we just
        // pad it with zeros. If its larger, we hash it and then pad it with
        // zeros.
        if key.len() <= hmac.i_key_pad.len() {
            for (k_idx, k_itm) in key.iter().enumerate() {
                hmac.i_key_pad[k_idx] ^= *k_itm;
                opad[k_idx] ^= *k_itm;
            }
        } else {
            let mut digest = D::default();
            digest.input(key);
            let output = digest.fixed_result();

            let n = min(output.len(), hmac.i_key_pad.len());
            for idx in 0..n {
                hmac.i_key_pad[idx] ^= output[idx];
                opad[idx] ^= output[idx];
            }
        }
        hmac.digest.input(&hmac.i_key_pad);
        hmac.opad_digest.input(&opad);

        Ok(hmac)
    }

    #[inline]
    fn input(&mut self, data: &[u8]) {
        self.digest.input(data);
    }

    #[inline]
    fn result(self) -> MacResult<D::OutputSize> {
        let mut opad_digest = self.opad_digest.clone();
        let hash = self.digest.fixed_result();
        opad_digest.input(&hash);
        MacResult::new(opad_digest.fixed_result())
    }

    #[inline]
    fn reset(&mut self) {
        self.digest.reset();
        self.digest.input(&self.i_key_pad);
    }
}

impl<D> Clone for Hmac<D>
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
{
    fn clone(&self) -> Hmac<D> {
        Hmac {
            digest: self.digest.clone(),
            i_key_pad: self.i_key_pad.clone(),
            opad_digest: self.opad_digest.clone(),
        }
    }
}

impl<D> fmt::Debug for Hmac<D>
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone + fmt::Debug,
    D::BlockSize: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Hmac")
            .field("digest", &self.digest)
            .field("i_key_pad", &self.i_key_pad)
            .field("opad_digest", &self.opad_digest)
            .finish()
    }
}
