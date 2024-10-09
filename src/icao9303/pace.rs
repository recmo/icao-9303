use {
    super::Icao9303,
    crate::{
        icao9303::{
            asn1::{
                security_info::{KeyAgreement, PaceInfo, SecurityInfo},
                EfDg14,
            },
            secure_messaging::{aes::kdf_128, SymmetricCipher},
            seed_from_mrz,
        },
        tr03111::{ecka, ECAlgoParameters, EcParameters, EllipticCurve},
    },
    anyhow::{anyhow, ensure, Result},
    der::{asn1::ObjectIdentifier as Oid, Decode},
    rand::{CryptoRng, RngCore},
    sha1::{Digest, Sha1},
};

pub const KDF_PACE: u32 = 3;

impl Icao9303 {
    pub fn pace(&mut self, rng: impl CryptoRng + RngCore, mrz: &str) -> Result<()> {
        // Derive symmetric key K_pi
        let k = k_from_mrz(mrz);
        let k_pi = kdf_128(&k[..], KDF_PACE);

        // Send MSE:Set AT.

        // Send GENERAL AUTHENTICATE

        todo!()
    }
}

pub fn k_from_mrz(mrz: &str) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(mrz.as_bytes());
    hasher.finalize().into()
}

/// ICAO 9303-11 9.5.1
pub fn standardized_parameters(id: u64) -> Option<EcParameters> {
    match id {
        0 => todo!(),
        1 => todo!(),
        2 => todo!(),
        3..=7 => todo!(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::icao9303::secure_messaging::aes::{kdf_128, kdf_256},
        hex_literal::hex,
    };

    // ICAO 9303-11, Appendix G
    #[test]
    fn test_pace_example() {
        let mrz = "T22000129364081251010318";
        let k = k_from_mrz(mrz);
        assert_eq!(k, hex!("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD"));
        let k_pi = kdf_128(&k[..], 3);
        assert_eq!(k_pi, hex!("89DED1B2 6624EC1E 634C1989 302849DD"));

        let pace_info = PaceInfo::from_der(&hex!("3012060A 04007F00 07020204 02020201 0202010D"));
        dbg!(pace_info);
    }
}
