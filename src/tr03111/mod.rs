mod elliptic_curve;
mod named_curves;
mod prime_field;

pub use self::{
    elliptic_curve::{EllipticCurve, EllipticCurvePoint},
    prime_field::{PrimeField, PrimeFieldElement},
};
use {
    anyhow::{ensure, Result},
    der::asn1::{Int, IntRef, OctetString},
    ruint::aliases::U320,
};

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
