use {der::asn1::ObjectIdentifier as Oid, hex_literal::hex};

// https://www.rfc-editor.org/rfc/rfc5114
// https://www.secg.org/sec2-v2.pdf
// Some OIDs are from ANSI X9.62, others from Certicom
pub const ID_SEC_P192R1: Oid = Oid::new_unwrap("1.2.840.10045.3.1.1");
pub const ID_SEC_P224R1: Oid = Oid::new_unwrap("1.3.132.0.33");
pub const ID_SEC_P256R1: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
pub const ID_SEC_P384R1: Oid = Oid::new_unwrap("1.3.132.0.34");
pub const ID_SEC_P521R1: Oid = Oid::new_unwrap("1.3.132.0.35");

// https://www.rfc-editor.org/rfc/rfc5639
pub const ID_BRAINPOOL_P192R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.3");
pub const ID_BRAINPOOL_P224R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.5");
pub const ID_BRAINPOOL_P256R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.7");
pub const ID_BRAINPOOL_P320R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.9");
pub const ID_BRAINPOOL_P384R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.11");
pub const ID_BRAINPOOL_P512R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.13");

// EcParameters objects
pub const EC_SEC_P192R1: &'static [u8] = &hex!(
    "

"
);

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{Curve, EcParameters, FieldId, ID_PRIME_FIELD},
            *,
        },
        crate::tr03111::PrimeField,
        der::asn1::OctetString,
    };

    #[test]
    fn test_ec_param() {
        todo!();

        let ec = EcParameters {
            version: 1,
            field_id: FieldId {
                field_type: ID_PRIME_FIELD,
                parameters: OctetString::new(hex!("E95E4A5F737059DC60DFC7AD95B3D8139515620F"))
                    .unwrap()
                    .into(),
            },
            curve: Curve {
                a: OctetString::new(hex!("340E7BE2A280EB74E2BE61BADA745D97E8F7C300"))
                    .unwrap()
                    .into(),
                b: OctetString::new(hex!("1E589A8595423412134FAA2DBDEC95C8D8675E58"))
                    .unwrap()
                    .into(),
                seed: None,
            },
        };
    }
}
