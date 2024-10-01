mod elliptic_curve;
mod prime_field;

pub use self::{elliptic_curve::EllipticCurve, prime_field::PrimeField};
use {
    anyhow::{ensure, Result},
    der::{
        asn1::{BitString, Int, IntRef, Null, ObjectIdentifier as Oid, OctetString},
        Any, Choice, Sequence, ValueOrd,
    },
    elliptic_curve::EllipticCurvePoint,
    prime_field::PrimeFieldElement,
    ruint::aliases::U320,
};

// See TR-03111
// ANSI X9.62 1.2.840.10045
// public key 2
// elliptic curve 1
pub const ID_EC_PUBLIC_KEY: Oid = oid("1.2.840.10045.2.1");
pub const ID_PRIME_FIELD: Oid = oid("1.2.840.10045.1.1");

/// RFC 5280 `AlgorithmIdentifier`
/// This deviates from RFC 5280 by using `Any` for parameters
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct AlgorithmIdentifier {
    pub algorithm: Oid,
    pub parameters: ECAlgoParameters,
}

/// Elliptic Curve Algorithm Parameters.
///
/// **Note**: This deviates from RFC 5480 by allowing for explicit
/// parameters using `EcParameters` in addition to named curves. This
/// is used by at least some Dutch eMRTDs.
///
/// [TR-03111] `Parameters`
/// Details on parameters in [TR-03111]
#[derive(Clone, Debug, Eq, PartialEq, Choice, ValueOrd)]
pub enum ECAlgoParameters {
    EcParameters(EcParameters),
    NamedCurve(Oid),
    ImplicitlyCA(Null),
}

// TODO: Make by Ref.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct EcParameters {
    pub version: u64,
    pub field_id: FieldID,
    pub curve: Curve,
    pub base: ECPoint,
    pub order: Int,
    pub cofactor: Option<Int>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct FieldID {
    pub field_type: Oid,
    pub parameters: Any,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct Curve {
    pub a: FieldElement,
    pub b: FieldElement,
    pub seed: Option<BitString>,
}

pub type FieldElement = OctetString;

pub type ECPoint = OctetString;

/// TODO: Deduplicate and move to some utility module
const fn oid(oid: &'static str) -> Oid {
    Oid::new_unwrap(oid)
}

/// Elliptic Curve Key Agreement
/// See TR-03111 section 4.3.1
pub fn ecka<'a>(
    private_key: PrimeFieldElement,
    public_key: EllipticCurvePoint<'a>,
) -> Result<(EllipticCurvePoint<'a>, Vec<u8>)> {
    let curve = public_key.curve();
    ensure!(private_key.field() == curve.scalar_field());

    let h = curve.cofactor();
    let l = curve.scalar_field().el_from_uint(h).inv().unwrap();
    let q = h * public_key;
    let s_ab = (private_key * l) * q;
    ensure!(s_ab != curve.pt_infinity());
    let z_ab = s_ab.x().unwrap().fe2os();

    Ok((s_ab, z_ab))
}

pub fn parse_uint(int: &Int) -> Result<U320> {
    // Get twos-complement big-endian bytes
    let mut big_endian = int.as_bytes();

    // Can not be empty (zero is encoded as 0x00).
    ensure!(!big_endian.is_empty());

    // Ensure the number is positive
    ensure!(big_endian[0] & 0x80 == 0, "Modulus is negative");
    if big_endian[0] == 0x00 {
        // Split of leading zero.
        big_endian = &big_endian[1..];
    }

    // Ensure the number is not too large
    ensure!(big_endian.len() <= 40, "Modulus is too large");

    // Zero extend to 320 bits
    let mut zero_extended = [0; 40];
    zero_extended[40 - big_endian.len()..].copy_from_slice(big_endian);

    // Parse as U320
    let uint = U320::from_be_slice(&zero_extended);
    Ok(uint)
}

pub fn parse_uint_ref(int: IntRef<'_>) -> Result<U320> {
    // Get twos-complement big-endian bytes
    let mut big_endian = int.as_bytes();

    // Can not be empty (zero is encoded as 0x00).
    ensure!(!big_endian.is_empty());

    // Ensure the number is positive
    ensure!(big_endian[0] & 0x80 == 0, "Modulus is negative");
    if big_endian[0] == 0x00 {
        // Split of leading zero.
        big_endian = &big_endian[1..];
    }

    // Ensure the number is not too large
    ensure!(big_endian.len() <= 40, "Modulus is too large");

    // Zero extend to 320 bits
    let mut zero_extended = [0; 40];
    zero_extended[40 - big_endian.len()..].copy_from_slice(big_endian);

    // Parse as U320
    let uint = U320::from_be_slice(&zero_extended);
    Ok(uint)
}

pub fn parse_uint_os(os: &OctetString) -> Result<U320> {
    // Get twos-complement big-endian bytes
    let big_endian = os.as_bytes();

    // TODO: Length should be exactly length of modulus in bytes.

    // Ensure the number is not too large
    ensure!(big_endian.len() <= 40, "Modulus is too large");

    // Zero extend to 320 bits
    let mut zero_extended = [0; 40];
    zero_extended[40 - big_endian.len()..].copy_from_slice(big_endian);

    // Parse as U320
    let uint = U320::from_be_slice(&zero_extended);
    Ok(uint)
}
