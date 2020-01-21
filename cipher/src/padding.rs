use super::into_blocks;
use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PaddingError {
    InvalidBlockSize,
    InvalidPadding,
}

impl fmt::Display for PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PaddingError::InvalidPadding => write!(f, "Invalid PKCS#7 padding"),
            PaddingError::InvalidBlockSize => write!(f, "Some blocks are not of the block size"),
        }
    }
}
impl Error for PaddingError {
    fn description(&self) -> &str {
        match *self {
            PaddingError::InvalidPadding => "Invalid PKCS#7 padding",
            PaddingError::InvalidBlockSize => "Some blocks are not of the block size",
        }
    }
}
pub fn add(blocks: &mut Vec<Vec<u8>>, size: u8) -> Result<(), PaddingError> {
    if !is_valid_nonpad(blocks, size) {
        return Err(PaddingError::InvalidBlockSize);
    }
    if is_exact_multiple(blocks, size) {
        blocks.push(vec![size as u8; size as usize]);
    } else if let Some(last_block) = blocks.last_mut() {
        let padding_len: u8 = size - last_block.len() as u8;
        last_block.append(&mut vec![padding_len; padding_len as usize]);
    }
    Ok(())
}

pub fn remove(blocks: &mut Vec<Vec<u8>>, size: u8) -> Result<(), PaddingError> {
    if !is_valid_padding(&blocks, size) {
        return Err(PaddingError::InvalidPadding);
    }

    let pad_len: u8 = *blocks.last().unwrap().last().unwrap();
    if pad_len == size {
        blocks.pop();
    } else {
        let last = blocks.last_mut().unwrap();
        last.truncate((size - pad_len) as usize);
    }
    Ok(())
}

// @dev: this is the public facing function
/// Validate padding of a decrypted ciphertext
pub fn validate_padding(pt: &[u8], block_size: u8) -> bool {
    let pt_2d = into_blocks(&pt, block_size as usize);
    is_valid_padding(&pt_2d, block_size)
}

// @dev: this is internal core logic to validate padding with a 2D vector parameter
fn is_valid_padding(blocks: &[Vec<u8>], size: u8) -> bool {
    let pad_len: u8 = *blocks.last().unwrap().last().unwrap();

    if !is_exact_multiple(&blocks, size) || pad_len == 0 || pad_len > 16 {
        return false;
    }

    let mut last_block: Vec<u8> = blocks.last().unwrap().clone();
    for _ in 0..pad_len {
        if last_block.pop() != Some(pad_len) {
            return false;
        }
    }
    if last_block.pop() == Some(pad_len) {
        return false;
    }
    true
}

fn is_valid_nonpad(blocks: &[Vec<u8>], size: u8) -> bool {
    for block in blocks.iter().take(blocks.len() - 1) {
        if block.len() != size as usize {
            return false;
        }
    }
    true
}

fn is_exact_multiple(blocks: &[Vec<u8>], size: u8) -> bool {
    for block in blocks.iter() {
        if block.len() != size as usize {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::super::into_blocks;
    use super::*;

    #[test]
    fn add_padding() {
        let mut blocks = into_blocks(&b"YELLOW SUBMARINE".to_vec(), 20);
        let result = add(&mut blocks, 20);
        assert!(result.is_ok());
        assert_eq!(blocks[0], b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }

    #[test]
    fn remove_padding() {
        let mut blocks = into_blocks(&b"ICE ICE BABY\x04\x04\x04\x04".to_vec(), 16);
        let result = remove(&mut blocks, 16);
        assert!(result.is_ok());
        assert_eq!(blocks[0], b"ICE ICE BABY");
    }

    #[test]
    fn padding_validation() {
        assert!(validate_padding(
            &b"ICE ICE BABY\x04\x04\x04\x04".to_vec(),
            16
        ));
        assert!(!validate_padding(&b"yellow submarine\x00".to_vec(), 16));
        assert!(!validate_padding(&b"ICE ICE BABY\x03\x03\x03".to_vec(), 16));
        assert!(!validate_padding(&b"ICE ICE BABY".to_vec(), 16));
    }
}
