mod chip_authentication_info;
mod pace_info;

pub use {
    self::pace_info::{PaceInfo, PaceProtocol},
    chip_authentication_info::{
        ChipAuthenticationInfo, ChipAuthenticationProtocol, ChipAuthenticationPublicKeyInfo,
    },
};
use {
    crate::{ensure_err, icao9303::secure_messaging::SymmetricCipher},
    der::{
        asn1::{ObjectIdentifier as Oid, SetOfVec},
        Any, Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind, FixedTag, Header, Length,
        Reader, Result, Sequence, Tag, ValueOrd, Writer,
    },
    pace_info::PaceDomainParameterInfo,
    std::{
        cmp::Ordering,
        fmt::{self, Display, Formatter},
    },
};

pub const KEY_AGREEMENT_OID: Oid = Oid::new_unwrap("0.4.0.127.0.7.2.2.1");
pub const ID_ACTIVE_AUTHENTICATION: Oid = Oid::new_unwrap("2.23.136.1.1.5");
pub const ID_TERMINAL_AUTHENTICATION: Oid = Oid::new_unwrap("0.4.0.127.0.7.2.2.2");

/// A [`SecurityInfos`] object from ICAO-9303-11 9.2.
///
/// ```asn1
/// SecurityInfos ::= SET OF SecurityInfo
/// ```
pub type SecurityInfos = SetOfVec<SecurityInfo>;

/// Various subtypes of `SecurityInfo` from ICAO-9303-11 9.2.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SecurityInfo {
    Pace(PaceInfo),
    PaceDomainParameter(PaceDomainParameterInfo),
    ChipAuthentication(ChipAuthenticationInfo),
    ChipAuthenticationPublicKey(ChipAuthenticationPublicKeyInfo),
    ActiveAutentication(ActiveAuthenticationInfo),
    TerminalAuthentication(TerminalAuthenticationInfo),
    Unknow(AnySecurityInfo),
}

/// A [`SecurityInfo`] object from ICAO-9303-11 9.2.
///
/// ```asn1
/// SecurityInfo ::= SEQUENCE {
///     protocol OBJECT IDENTIFIER,
///     requiredData ANY DEFINED BY protocol,
///     optionalData ANY DEFINED BY protocol OPTIONAL
/// }
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Sequence, ValueOrd)]
pub struct AnySecurityInfo {
    pub protocol: Oid,
    pub required_data: Any,
    pub optional_data: Option<Any>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyAgreement {
    /// Diffie-Hellman over a prime field.
    Dh,

    /// Elliptic Curve Diffie-Hellman.
    Ecdh,
}

pub type ActiveAuthenticationInfo = Any; // TODO
pub type TerminalAuthenticationInfo = Any; // TODO

impl Sequence<'_> for SecurityInfo {}

impl ValueOrd for SecurityInfo {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        let self_der = self.to_der()?;
        let other_der = other.to_der()?;
        let self_any = AnySecurityInfo::from_der(&self_der)?;
        let other_any = AnySecurityInfo::from_der(&other_der)?;
        self_any.value_cmp(&other_any)
    }
}

impl EncodeValue for SecurityInfo {
    fn value_len(&self) -> Result<Length> {
        match self {
            Self::Pace(info) => info.value_len(),
            Self::PaceDomainParameter(info) => info.value_len(),
            Self::ChipAuthentication(info) => info.value_len(),
            Self::ChipAuthenticationPublicKey(info) => info.value_len(),
            Self::ActiveAutentication(info) => info.value_len(),
            Self::TerminalAuthentication(info) => info.value_len(),
            Self::Unknow(info) => info.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Self::Pace(info) => info.encode_value(writer),
            Self::PaceDomainParameter(info) => info.encode_value(writer),
            Self::ChipAuthentication(info) => info.encode_value(writer),
            Self::ChipAuthenticationPublicKey(info) => info.encode_value(writer),
            Self::ActiveAutentication(info) => info.encode_value(writer),
            Self::TerminalAuthentication(info) => info.encode_value(writer),
            Self::Unknow(info) => info.encode_value(writer),
        }
    }
}

impl<'a> DecodeValue<'a> for SecurityInfo {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        let offset = reader.position();
        let offset_err = |err: Error| {
            Error::new(
                err.kind(),
                err.position()
                    .map_or(offset, |p| (p + offset).unwrap_or(offset)),
            )
        };
        let any = AnySecurityInfo::decode_value(reader, header)?;
        let der = any.to_der()?;
        dbg!(&any.protocol);
        dbg!(hex::encode(&der));
        if let Ok(protocol) = PaceProtocol::try_from(any.protocol) {
            if protocol.cipher.is_some() {
                dbg!();
                PaceInfo::from_der(&der).map_err(offset_err).map(Self::Pace)
            } else {
                dbg!();
                PaceDomainParameterInfo::from_der(&der)
                    .map_err(offset_err)
                    .map(Self::PaceDomainParameter)
            }
        } else if ChipAuthenticationProtocol::try_from(any.protocol).is_ok() {
            dbg!();
            ChipAuthenticationInfo::from_der(&der)
                .map_err(offset_err)
                .map(Self::ChipAuthentication)
        } else if KeyAgreement::try_from(any.protocol).is_ok() {
            dbg!();
            ChipAuthenticationPublicKeyInfo::from_der(&der)
                .map_err(offset_err)
                .map(Self::ChipAuthenticationPublicKey)
        } else if any.protocol == ID_ACTIVE_AUTHENTICATION {
            dbg!();
            ActiveAuthenticationInfo::from_der(&der)
                .map_err(offset_err)
                .map(Self::ActiveAutentication)
        } else if any.protocol == ID_TERMINAL_AUTHENTICATION {
            dbg!();
            // TODO: TerminalAuthentication protocol IDs
            TerminalAuthenticationInfo::from_der(&der)
                .map_err(offset_err)
                .map(Self::TerminalAuthentication)
        } else {
            dbg!();
            Ok(Self::Unknow(any))
        }
    }
}

impl Display for KeyAgreement {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Dh => write!(f, "DH"),
            Self::Ecdh => write!(f, "ECDH"),
        }
    }
}

impl TryFrom<Oid> for KeyAgreement {
    type Error = Error;

    fn try_from(oid: Oid) -> Result<Self> {
        let err = Error::new(ErrorKind::OidUnknown { oid }, Length::ZERO);
        ensure_err!(oid.parent() == Some(KEY_AGREEMENT_OID), err);
        match oid.arc(9) {
            Some(1) => Ok(KeyAgreement::Dh),
            Some(2) => Ok(KeyAgreement::Ecdh),
            _ => Err(err),
        }
    }
}

impl From<KeyAgreement> for Oid {
    fn from(ka: KeyAgreement) -> Self {
        KEY_AGREEMENT_OID
            .push_arc(match ka {
                KeyAgreement::Dh => 1,
                KeyAgreement::Ecdh => 2,
            })
            .unwrap()
    }
}

impl FixedTag for KeyAgreement {
    const TAG: Tag = Oid::TAG;
}

impl EncodeValue for KeyAgreement {
    fn value_len(&self) -> Result<Length> {
        Oid::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        Oid::from(*self).encode_value(writer)
    }
}

impl<'a> DecodeValue<'a> for KeyAgreement {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Oid::decode_value(reader, header).and_then(|oid| {
            Self::try_from(oid).map_err(|err| Error::new(err.kind(), reader.position()))
        })
    }
}
