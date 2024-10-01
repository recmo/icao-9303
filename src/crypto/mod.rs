//! Cryptographic algorithms and utility functions.

pub mod tdes;

use sha1::{Digest, Sha1};

pub fn pad(bytes: &mut Vec<u8>, block_size: usize) {
    bytes.push(0x80);
    bytes.resize(bytes.len().next_multiple_of(block_size), 0x00);
}

pub fn seed_from_mrz(mrz: &str) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(mrz.as_bytes());
    let hash = hasher.finalize();
    hash[0..16].try_into().unwrap()
}
