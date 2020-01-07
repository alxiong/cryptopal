fn pad_block(block: &[u8], size: u8) -> Vec<u8> {
    let padding_len: u8 = size - block.len() as u8;
    let mut padded = block.to_vec();
    padded.append(&mut vec![padding_len; padding_len as usize]);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding() {
        assert_eq!(
            pad_block(&"YELLOW SUBMARINE".as_bytes(), 20 as u8),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }
}
