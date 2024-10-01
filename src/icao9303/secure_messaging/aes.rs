use {
    super::{parse_apdu, Cipher, SecureMessaging},
    crate::{
        icao9303::secure_messaging::{KDF_ENC, KDF_MAC},
        iso7816::StatusWord,
    },
    aes::{Aes128, Aes192, Aes256},
    anyhow::Result,
    cbc::{Decryptor, Encryptor},
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    cmac::{Cmac, Mac},
    sha1::{Digest, Sha1},
    sha2::Sha256,
};

type Aes256Cbc = Encryptor<Aes256>;
type Aes256Cmac = Cmac<Aes256>;

// All AES variantes have the same block size
const BLOCK_SIZE: usize = 16;

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

pub struct Aes256Cipher {
    kenc: [u8; 32],
    kmac: [u8; 32],
}

impl Aes256Cipher {
    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            kenc: kdf_256(seed, KDF_ENC),
            kmac: kdf_256(seed, KDF_MAC),
        }
    }
}

impl Cipher for Aes256Cipher {
    fn block_size(&self) -> usize {
        16
    }

    fn enc(&mut self, data: &mut [u8]) {
        todo!()
    }

    fn dec(&mut self, data: &mut [u8]) {
        todo!()
    }

    fn mac(&mut self, data: &[u8]) -> [u8; 8] {
        todo!()
    }
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

    // Example TR 03110 Worked Example 5
    #[test]
    fn test_derive_keys_2() {
        let shared_secret = hex!(
            "
            79 1D A0 42 73 CC FE 86 2E 52 DF 60 34 7E 25 57
            19 2E 1F 8D 75 17 82 2C E3 D3 06 05 6C 1C DE B4
            42 87 B3 07 2A 3E DC 60"
        );
        let k_enc = hex!("94 AB CD 27 1A B7 D9 A5 59 0B A5 2C B5 18 B8 31");
        let k_mac = hex!("78 B5 70 9E 7A BE DB 18 5B 42 4D 0E E3 A8 24 99 ");

        assert_eq!(kdf_128(&shared_secret, KDF_ENC), k_enc);
        assert_eq!(kdf_128(&shared_secret, KDF_MAC), k_mac);
    }
}
