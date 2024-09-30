//! Algorithms and OIDs from BSI TR-03110-3

use {
    crate::{
        icao9303::SecurityInfo,
        tr03111::{AlgorithmIdentifier, ID_EC_PUBLIC_KEY},
    },
    anyhow::{ensure, Error, Result},
    const_oid::ObjectIdentifier as Oid,
    der::{
        asn1::{BitString, ObjectIdentifier},
        Decode, Encode, Sequence, ValueOrd,
    },
};

pub const ID_ACTIVE_AUTHENTICATION: Oid = oid("2.23.136.1.1.5");

// BSI TR-03110-3
// bsi-de 0.4.0.127.0.7
// chip authentication 2.2.1
// DH 1, ECDH 2
pub const ID_PK_DH: Oid = oid("0.4.0.127.0.7.2.2.1.1");
pub const ID_PK_ECDH: Oid = oid("0.4.0.127.0.7.2.2.1.2");

pub const ID_TERMINAL_AUTHENTICATION: Oid = oid("0.4.0.127.0.7.2.2.2");

// BSI TR-03110-3
// bsi-de 0.4.0.127.0.7
// chip authentication 2.2.3
// DH 1, ECDH 2
pub const ID_CA_DH: Oid = oid("0.4.0.127.0.7.2.2.3.1");
pub const ID_CA_DH_3DES_CBC_CBC: Oid = oid("0.4.0.127.0.7.2.2.3.1.1");
pub const ID_CA_DH_AES_CBC_CMAC_128: Oid = oid("0.4.0.127.0.7.2.2.3.1.2");
pub const ID_CA_DH_AES_CBC_CMAC_192: Oid = oid("0.4.0.127.0.7.2.2.3.1.3");
pub const ID_CA_DH_AES_CBC_CMAC_256: Oid = oid("0.4.0.127.0.7.2.2.3.1.4");
pub const ID_CA_ECDH: Oid = oid("0.4.0.127.0.7.2.2.3.2");
pub const ID_CA_ECDH_3DES_CBC_CBC: Oid = oid("0.4.0.127.0.7.2.2.3.2.1");
pub const ID_CA_ECDH_AES_CBC_CMAC_128: Oid = oid("0.4.0.127.0.7.2.2.3.2.2");
pub const ID_CA_ECDH_AES_CBC_CMAC_192: Oid = oid("0.4.0.127.0.7.2.2.3.2.3");
pub const ID_CA_ECDH_AES_CBC_CMAC_256: Oid = oid("0.4.0.127.0.7.2.2.3.2.4");

/// TR03110-3 `SecurityInfo`
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct ChipAuthenticationInfo {
    pub protocol: ObjectIdentifier,
    pub version: u64,
    pub key_id: Option<u64>,
}

/// TR03110-3 `ChipAuthenticationPublicKeyInfo`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct ChipAuthenticationPublicKeyInfo {
    pub protocol: ObjectIdentifier,
    pub chip_authentication_public_key: SubjectPublicKeyInfo,
    pub key_id: Option<u64>,
}

/// RFC 5280 `SubjectPublicKeyInfo`
/// Also in ICAO 9303-11 and TR 03110-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

pub const fn oid_name(oid: Oid) -> &'static str {
    match oid {
        ID_ACTIVE_AUTHENTICATION => "ACTIVE-AUTHENTICATION",
        ID_PK_DH => "PK-DH",
        ID_PK_ECDH => "PK-ECDH",
        ID_TERMINAL_AUTHENTICATION => "TERMINAL-AUTHENTICATION",
        ID_CA_DH => "CA-DH",
        ID_CA_DH_3DES_CBC_CBC => "CA-DH-3DES-CBC-CBC",
        ID_CA_DH_AES_CBC_CMAC_128 => "CA-DH-AES-CBC-CMAC-128",
        ID_CA_DH_AES_CBC_CMAC_192 => "CA-DH-AES-CBC-CMAC-192",
        ID_CA_DH_AES_CBC_CMAC_256 => "CA-DH-AES-CBC-CMAC-256",
        ID_CA_ECDH_3DES_CBC_CBC => "CA-ECDH-3DES-CBC-CBC",
        ID_CA_ECDH => "CA-ECDH",
        ID_CA_ECDH_AES_CBC_CMAC_128 => "CA-ECDH-AES-CBC-CMAC-128",
        ID_CA_ECDH_AES_CBC_CMAC_192 => "CA-ECDH-AES-CBC-CMAC-192",
        ID_CA_ECDH_AES_CBC_CMAC_256 => "CA-ECDH-AES-CBC-CMAC-256",

        ID_EC_PUBLIC_KEY => "EC-PUBLIC-KEY",
        _ => "Unknown",
    }
}

const fn oid(oid: &'static str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(oid)
}

impl ChipAuthenticationInfo {
    pub fn algorithm_name(&self) -> &'static str {
        oid_name(self.protocol)
    }
}

impl<'a> TryFrom<&SecurityInfo<'a>> for ChipAuthenticationInfo {
    type Error = Error;

    fn try_from(info: &SecurityInfo) -> Result<Self> {
        ensure!(
            matches!(
                info.protocol,
                ID_CA_DH_3DES_CBC_CBC
                    | ID_CA_DH_AES_CBC_CMAC_128
                    | ID_CA_DH_AES_CBC_CMAC_192
                    | ID_CA_DH_AES_CBC_CMAC_256
                    | ID_CA_ECDH_3DES_CBC_CBC
                    | ID_CA_ECDH_AES_CBC_CMAC_128
                    | ID_CA_ECDH_AES_CBC_CMAC_192
                    | ID_CA_ECDH_AES_CBC_CMAC_256
            ),
            "Invalid ChipAuthenticationInfo protocol"
        );
        let mut buf = Vec::new();
        info.encode_to_vec(&mut buf)?;
        let ca = ChipAuthenticationInfo::from_der(&buf)?;
        ensure!(
            ca.protocol == info.protocol,
            "ChipAuthenticationInfo protocol mismatch"
        );
        Ok(ca)
    }
}

impl<'a> TryFrom<&SecurityInfo<'a>> for ChipAuthenticationPublicKeyInfo {
    type Error = Error;

    fn try_from(info: &SecurityInfo) -> Result<Self> {
        ensure!(
            matches!(info.protocol, ID_PK_DH | ID_PK_ECDH),
            "Invalid ChipAuthenticationPublicKeyInfo protocol"
        );
        let mut buf = Vec::new();
        info.encode_to_vec(&mut buf)?;
        let res = ChipAuthenticationPublicKeyInfo::from_der(&buf)?;
        ensure!(
            res.protocol == info.protocol,
            "ChipAuthenticationPublicKeyInfo protocol mismatch"
        );
        Ok(res)
    }
}
