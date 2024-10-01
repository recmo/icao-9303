use {
    crate::icao9303::secure_messaging::{KDF_ENC, KDF_MAC},
    sha1::{Digest, Sha1},
    sha2::Sha256,
};

/// Key Derivation Function (KDF) for 128-bit AES keys.
/// ICAO 9303-11 section 9.7.1.2
pub fn kdf_128(secret: &[u8], counter: u32) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(secret);
    hasher.update(counter.to_be_bytes());
    let hash = hasher.finalize();
    hash[0..16].try_into().unwrap()
}

/// Key Derivation Function (KDF) for 192-bit AES keys.
/// ICAO 9303-11 section 9.7.1.2
pub fn kdf_192(secret: &[u8], counter: u32) -> [u8; 24] {
    kdf_256(secret, counter)[0..24].try_into().unwrap()
}

/// Key Derivation Function (KDF) for 256-bit AES keys.
/// ICAO 9303-11 section 9.7.1.2
pub fn kdf_256(secret: &[u8], counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(counter.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use {super::*, crate::crypto::seed_from_mrz, hex_literal::hex};

    // Example ICAO 9303-11 section G.2
    #[test]
    fn test_derive_keys() {
        let shared_secret = hex!(
            "
            6BABC7B3 A72BCD7E A385E4C6 2DB2625B
            D8613B24 149E146A 629311C4 CA6698E3
            8B834B6A 9E9CD718 4BA8834A FF5043D4
            36950C4C 1E783236 7C10CB8C 314D40E5
            990B0DF7 013E64B4 549E2270 923D06F0
            8CFF6BD3 E977DDE6 ABE4C31D 55C0FA2E
            465E553E 77BDF75E 3193D383 4FC26E8E
            B1EE2FA1 E4FC97C1 8C3F6CFF FE2607FD
            "
        );
        let k_enc = hex!("2F7F46AD CC9E7E52 1B45D192 FAFA9126");
        let k_mac = hex!("805A1D27 D45A5116 F73C5446 9462B7D8");

        assert_eq!(kdf_128(&shared_secret, KDF_ENC), k_enc);
        assert_eq!(kdf_128(&shared_secret, KDF_MAC), k_mac);
    }
}
