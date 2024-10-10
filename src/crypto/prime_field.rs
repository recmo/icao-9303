use {
    super::parse_uint,
    crate::{asn1::public_key::FieldId, ensure_err},
    anyhow::{bail, ensure, Result},
    rand::{CryptoRng, Rng, RngCore},
    ruint::aliases::U64,
    std::{
        fmt::{self, Debug, Formatter},
        ops::{Add, AddAssign, Deref, Div, Mul, MulAssign, Neg, Sub},
    },
};

// The largest prime field we support is 576 bits.
// This covers all the named curves, including secp521r1.
pub type Uint = ruint::Uint<576, 9>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PrimeField {
    modulus: Uint,

    // Precomputed values for Montgomery multiplication.
    montgomery_r: Uint,  // R = 2^64*LIMBS mod modulus
    montgomery_r2: Uint, // R^2, or R in Montgomery form
    montgomery_r3: Uint, // R^3, or R^2 in Montgomery form
    mod_inv: u64,        // -1 / modulus mod 2^64
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrimeFieldElement<'a> {
    field: &'a PrimeField,
    value: Uint,
}

// TODO: Configurable reference to field.
// #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
// pub struct PrimeFieldElement<F: Deref<PrimeField>> {
//     field: F,
//     value: U320,
// }

impl PrimeField {
    pub fn from_field_id(field_id: &FieldId) -> Result<Self> {
        let modulus = match field_id {
            FieldId::PrimeField { modulus } => modulus,
            _ => bail!("Field ID is not a prime field"),
        };
        let modulus = parse_uint(modulus)?;
        Ok(Self::from_modulus(modulus))
    }

    pub fn from_modulus(modulus: Uint) -> Self {
        assert_ne!(modulus, Uint::ZERO);
        let mod_inv = U64::wrapping_from(modulus)
            .inv_ring()
            .unwrap()
            .wrapping_neg()
            .to();
        let montgomery_r = Uint::from(2).pow_mod(Uint::from(Uint::BITS), modulus);
        let montgomery_r2 = montgomery_r.mul_mod(montgomery_r, modulus);
        let montgomery_r3 = montgomery_r2.mul_mod(montgomery_r, modulus);
        Self {
            modulus,
            mod_inv,
            montgomery_r,
            montgomery_r2,
            montgomery_r3,
        }
    }

    pub fn modulus(&self) -> Uint {
        self.modulus
    }

    pub fn byte_len(&self) -> usize {
        self.modulus().byte_len()
    }

    pub fn zero(&self) -> PrimeFieldElement {
        PrimeFieldElement {
            field: self,
            value: Uint::ZERO,
        }
    }

    pub fn one(&self) -> PrimeFieldElement {
        PrimeFieldElement {
            field: self,
            value: self.montgomery_r,
        }
    }

    #[inline]
    pub fn el_from_u64(&self, value: u64) -> PrimeFieldElement {
        self.el_from_uint(Uint::from(value))
    }

    #[inline]
    pub fn el_from_uint(&self, value: Uint) -> PrimeFieldElement {
        assert!(value < self.modulus);
        // Convert to Montgomery form by multiplying with R.
        PrimeFieldElement {
            field: self,
            value: self.mont_mul(value, self.montgomery_r2),
        }
    }

    #[inline]
    pub fn el_from_monty(&self, value: Uint) -> PrimeFieldElement {
        assert!(value < self.modulus);
        PrimeFieldElement { field: self, value }
    }

    /// TR-03111 section 4.1.1 Algorithm 1
    pub fn random_nonzero(&self, mut rng: impl CryptoRng + RngCore) -> PrimeFieldElement {
        loop {
            let mut value = rng.gen::<Uint>();
            // Zero out the high bits.
            for b in self.modulus().bit_len()..Uint::BITS {
                value.set_bit(b, false);
            }
            if value != Uint::ZERO && value < self.modulus {
                return self.el_from_monty(value);
            }
        }
    }

    /// Implements TR-03111 section 3.1.3 OS2FE procedure.
    ///
    /// Note that it does not have any requirement on the input length and requires
    /// the reader to apply the modular reduction. Note that this violates the unique
    /// encoding property of DER encoding, but we'll apply the robustness principle and
    /// allow it.
    ///
    /// The matching encoding procedure, however, does specify an exact length.
    pub fn os2fe<T: AsRef<[u8]>>(&self, os: T) -> PrimeFieldElement {
        let os = os.as_ref();
        // ensure!(
        //     os.len() != self.modulus.byte_len(),
        //     "OS2FE input length does not match modulus length"
        // );
        // Do modular reduction per TR-03111.
        let mut result = self.zero();
        let base = self.el_from_u64(256);
        for byte in os {
            result *= base;
            result += self.el_from_u64(*byte as u64);
        }
        result
    }

    /// Montogomery multiplication
    #[inline]
    fn mont_mul(&self, a: Uint, b: Uint) -> Uint {
        a.mul_redc(b, self.modulus, self.mod_inv)
    }
}

impl PrimeFieldElement<'_> {
    pub fn field(&self) -> &PrimeField {
        self.field
    }

    #[inline]
    pub fn to_uint(self) -> Uint {
        self.field.mont_mul(self.value, Uint::from(1))
    }

    #[inline]
    pub fn as_uint_monty(self) -> Uint {
        self.value
    }

    /// Implements TR-03111 section 3.1.3 FE2OS procedure.
    pub fn fe2os(&self) -> Vec<u8> {
        let mut result = self.to_uint().to_be_bytes_vec();
        // Trim excess leading zeros.
        result.split_off(result.len() - self.field.byte_len())
    }

    /// Exponentiation
    ///
    /// Run time may depend on the exponent.
    #[inline]
    pub fn pow(self, exponent: u64) -> Self {
        match exponent {
            0 => self.field.one(),
            1 => self,
            2 => self * self,
            3 => self * self * self,
            n if n % 2 == 0 => (self * self).pow(n / 2),
            n => self * self.pow(n - 1),
        }
    }

    /// Inversion
    ///
    /// Run time may depend on the value.
    #[inline]
    pub fn inv(self) -> Option<Self> {
        self.value
            .inv_mod(self.field.modulus)
            .map(|value| PrimeFieldElement {
                field: self.field,
                value: self.field.mont_mul(value, self.field.montgomery_r3),
            })
    }
}

macro_rules! forward_fmt {
    ($($type:ty),+) => {
        $(
            impl $type for PrimeFieldElement<'_> {
                fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                    <Uint as $type>::fmt(&self.to_uint(), f)
                }
            }
        )+
    };
}

forward_fmt!(
    fmt::Debug,
    fmt::Display,
    fmt::Binary,
    fmt::Octal,
    fmt::LowerHex,
    fmt::UpperHex
);

impl Add for PrimeFieldElement<'_> {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        assert_eq!(self.field, other.field);
        Self {
            field: self.field,
            value: self.value.add_mod(other.value, self.field.modulus),
        }
    }
}

impl Sub for PrimeFieldElement<'_> {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        assert_eq!(self.field, other.field);
        self + (-other)
    }
}

impl Mul for PrimeFieldElement<'_> {
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        assert_eq!(self.field, other.field);
        Self {
            field: self.field,
            value: self.field.mont_mul(self.value, other.value),
        }
    }
}

impl Neg for PrimeFieldElement<'_> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self {
            field: self.field,
            value: self.field.modulus - self.value,
        }
    }
}

impl Div for PrimeFieldElement<'_> {
    type Output = Option<Self>;

    /// Division
    ///
    /// Run time may depend on the value of the divisor.
    #[inline]
    fn div(self, other: Self) -> Option<Self> {
        assert_eq!(self.field, other.field);
        other.inv().map(|inv| self * inv)
    }
}

impl AddAssign for PrimeFieldElement<'_> {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl MulAssign for PrimeFieldElement<'_> {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}
