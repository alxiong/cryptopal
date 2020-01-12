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
    if !is_validate_nonpad(blocks, size) {
        return Err(PaddingError::InvalidBlockSize);
    }
    if is_exact_multiple(blocks, size) {
        blocks.push(vec![size as u8; size as usize]);
    } else {
        if let Some(last_block) = blocks.last_mut() {
            let padding_len: u8 = size - last_block.len() as u8;
            last_block.append(&mut vec![padding_len; padding_len as usize]);
        }
    }
    Ok(())
}

pub fn remove(blocks: &mut Vec<Vec<u8>>, size: u8) -> Result<(), PaddingError> {
    if !is_exact_multiple(blocks, size) {
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

fn is_validate_nonpad(blocks: &Vec<Vec<u8>>, size: u8) -> bool {
    for i in 0..blocks.len() - 1 {
        if blocks[i].len() != size as usize {
            return false;
        }
    }
    true
}

fn is_exact_multiple(blocks: &Vec<Vec<u8>>, size: u8) -> bool {
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
        let mut blocks = into_blocks(&"YELLOW SUBMARINE".as_bytes(), 20);
        let result = add(&mut blocks, 20);
        assert!(result.is_ok());
        assert_eq!(blocks[0], b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }

    #[test]
    fn remove_padding() {
        let mut blocks = into_blocks(&"ICE ICE BABY\x04\x04\x04\x04".as_bytes(), 16);
        let result = remove(&mut blocks, 16);
        assert!(result.is_ok());
        assert_eq!(blocks[0], b"ICE ICE BABY");
    }
}
