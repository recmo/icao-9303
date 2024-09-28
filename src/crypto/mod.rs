//! Cryptographic algorithms and utility functions.

pub mod tdes;

pub fn pad(bytes: &mut Vec<u8>) {
    bytes.push(0x80);
    bytes.resize(bytes.len().next_multiple_of(8), 0x00);
}
