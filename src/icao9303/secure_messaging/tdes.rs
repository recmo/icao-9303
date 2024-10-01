//! 3DES Secure Messasing

use {
    super::{Cipher, SecureMessaging, KDF_ENC, KDF_MAC},
    crate::{
        crypto::{
            pad,
            tdes::{dec_3des, enc_3des, mac_3des, set_parity_bits},
        },
        icao9303::secure_messaging::parse_apdu,
        iso7816::StatusWord,
    },
    anyhow::{anyhow, ensure, Result},
    sha1::{Digest, Sha1},
};

const BLOCK_SIZE: usize = 8;

pub struct TDesCipher {
    kenc: [u8; 16],
    kmac: [u8; 16],
}

pub fn kdf(seed: &[u8; 16], counter: u32) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(seed);
    hasher.update(counter.to_be_bytes());
    let hash = hasher.finalize();
    let mut key: [u8; 16] = hash[0..16].try_into().unwrap();
    set_parity_bits(&mut key);
    key
}

impl TDesCipher {
    pub fn from_seed(seed: [u8; 16]) -> Self {
        Self {
            kenc: kdf(&seed, KDF_ENC),
            kmac: kdf(&seed, KDF_MAC),
        }
    }
}

impl Cipher for TDesCipher {
    fn block_size(&self) -> usize {
        8
    }

    fn dec(&mut self, data: &mut [u8]) {
        dec_3des(&self.kenc, data);
    }

    fn enc(&mut self, data: &mut [u8]) {
        enc_3des(&self.kenc, data);
    }

    fn mac(&mut self, data: &[u8]) -> [u8; 8] {
        mac_3des(&self.kmac, data)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{crypto::seed_from_mrz, icao9303::secure_messaging::Encrypted},
        hex_literal::hex,
    };

    /// Example from ICAO 9303-11 section D.2
    #[test]
    fn test_bac_example() {
        let mrz = "L898902C<369080619406236";
        let seed = seed_from_mrz(mrz);
        assert_eq!(seed, hex!("239AB9CB282DAF66231DC5A4DF6BFBAE"));

        let (kenc, kmac) = (kdf(&seed, KDF_ENC), kdf(&seed, KDF_MAC));
        assert_eq!(kenc, hex!("AB94FDECF2674FDFB9B391F85D7F76F2"));
        assert_eq!(kmac, hex!("7962D9ECE03D1ACD4C76089DCE131543"));
    }

    // Example from ICAO 9303-11 section D.2
    #[test]
    fn test_derive_keys() {
        let k_seed = hex!("0036D272F5C350ACAC50C3F572D23600");
        let (kenc, kmac) = (kdf(&k_seed, KDF_ENC), kdf(&k_seed, KDF_MAC));
        assert_eq!(kenc, hex!("979EC13B1CBFE9DCD01AB0FED307EAE5"));
        assert_eq!(kmac, hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"));
    }

    // Example from ICAO 9303-11 section D.4
    #[test]
    fn test_tdes_sm() {
        let seed = hex!("0036D272F5C350ACAC50C3F572D23600");
        let ssc = 0x887022120C06C226;
        let mut tdes = Encrypted::new(TDesCipher::from_seed(seed), ssc);

        // Select EF.COM
        let apdu = hex!("00 A4 02 0C 02 01 1E");
        let papdu = tdes.enc_apdu(&apdu).unwrap();
        assert_eq!(
            papdu,
            hex!("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800")
        );
        let rapdu = hex!("990290008E08FA855A5D4C50A8ED");
        let dec = tdes.dec_response(0x9000.into(), &rapdu).unwrap();
        assert_eq!(dec, hex!(""));

        // Read Binary of first four bytes
        let apdu = hex!("00 B0 00 00 04");
        let papdu = tdes.enc_apdu(&apdu).unwrap();
        assert_eq!(papdu, hex!("0CB000000D9701048E08ED6705417E96BA5500"));
        let rapdu = hex!("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED");
        let data = tdes.dec_response(0x9000.into(), &rapdu).unwrap();
        assert_eq!(data, hex!("60145F01"));

        // Read Binary of remaining 18 bytes from offset 4
        let apdu = hex!("00 B0 00 04 12");
        let papdu = tdes.enc_apdu(&apdu).unwrap();
        assert_eq!(papdu, hex!("0CB000040D9701128E082EA28A70F3C7B53500"));
        let rapdu = hex!(
            "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D74"
        );
        let data = tdes.dec_response(0x9000.into(), &rapdu).unwrap();
        assert_eq!(data, hex!("04303130365F36063034303030305C026175"));
    }
}
