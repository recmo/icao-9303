//! Implements the required cryptography.
//!
//! Primarily based on TR-03111.

mod elliptic_curve;
mod named_curves;
mod prime_field;

pub use self::{
    elliptic_curve::{ecka, EllipticCurve, EllipticCurvePoint},
    prime_field::{PrimeField, PrimeFieldElement, Uint},
};
use {
    anyhow::{ensure, Result},
    der::asn1::{Int, OctetString},
};

fn parse_uint(int: &Int) -> Result<Uint> {
    // Get twos-complement big-endian bytes
    let mut big_endian = int.as_bytes();

    // Can not be empty (zero is encoded as 0x00).
    ensure!(!big_endian.is_empty());

    // Ensure the number is positive
    ensure!(big_endian[0] & 0x80 == 0, "Int is negative");
    if big_endian[0] == 0x00 {
        // Split of leading zero.
        big_endian = &big_endian[1..];
    }

    // Ensure the number is not too large
    ensure!(big_endian.len() <= Uint::BYTES, "Int is too large");

    // Zero extend to Uint::BITS bits
    let mut zero_extended = [0; Uint::BYTES];
    zero_extended[Uint::BYTES - big_endian.len()..].copy_from_slice(big_endian);

    // Parse as Uint
    let uint = Uint::from_be_slice(&zero_extended);
    Ok(uint)
}

pub fn parse_uint_os(os: &OctetString) -> Result<Uint> {
    // Get twos-complement big-endian bytes
    let big_endian = os.as_bytes();

    // TODO: Length should be exactly length of modulus in bytes.

    // Ensure the number is not too large
    ensure!(big_endian.len() <= 40, "Modulus is too large");

    // Zero extend to 320 bits
    let mut zero_extended = [0; 40];
    zero_extended[40 - big_endian.len()..].copy_from_slice(big_endian);

    // Parse as Uint
    let uint = Uint::from_be_slice(&zero_extended);
    Ok(uint)
}
