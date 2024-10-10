mod pubkey_algorithm_identifier;

pub use self::pubkey_algorithm_identifier::PubkeyAlgorithmIdentifier;
use der::{
    asn1::{BitString, Int, Null, ObjectIdentifier as Oid, OctetString},
    Any, Choice, Sequence, ValueOrd,
};

// See TR-03111
// ANSI X9.62 1.2.840.10045
// public key 2
// elliptic curve 1
pub const ID_EC_PUBLIC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
pub const ID_PRIME_FIELD: Oid = Oid::new_unwrap("1.2.840.10045.1.1");

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: PubkeyAlgorithmIdentifier,
    pub subject_public_key: BitString,
}

/// Elliptic Curve Algorithm Parameters.
///
/// **Note**: This deviates from RFC 5480 by allowing for explicit
/// parameters using `EcParameters` in addition to named curves. This
/// is used by at least some Dutch eMRTDs.
///
/// [TR-03111] `Parameters`
/// Details on parameters in [TR-03111]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Choice, ValueOrd)]
pub enum ECAlgoParameters {
    EcParameters(EcParameters),
    NamedCurve(Oid),
    ImplicitlyCA(Null),
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct EcParameters {
    pub version: u64,
    pub field_id: FieldId,
    pub curve: Curve,
    pub base: ECPoint,
    pub order: Int,
    pub cofactor: Option<Int>,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct FieldId {
    pub field_type: Oid,
    pub parameters: Any,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct Curve {
    pub a: FieldElement,
    pub b: FieldElement,
    pub seed: Option<BitString>,
}

pub type FieldElement = OctetString;

pub type ECPoint = OctetString;
