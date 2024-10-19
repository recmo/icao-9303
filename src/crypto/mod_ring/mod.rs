mod fields;
mod ruint;

use {
    num_traits::{One, PrimInt, Unsigned, Zero},
    std::{
        fmt::{self, Debug, Formatter},
        ops::{Add, AddAssign, Deref, Div, Mul, MulAssign, Neg, Sub, SubAssign},
    },
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
};

/// Trait for Uint backends supporting Montgomery multiplication.
pub trait UintMont:
    Sized + Copy + PartialEq + Eq + PartialOrd + Debug + Zero + One + Sub<Output = Self>
{
    fn parameters_from_modulus(modulus: Self) -> ModRing<Self>;
    fn mul_redc(self, other: Self, modulus: Self, mod_inv: u64) -> Self;
    fn add_mod(self, other: Self, modulus: Self) -> Self;
    fn inv_mod(self, modulus: Self) -> Option<Self>;
}

/// Trait for Uint backends that can be used for exponentiation.
pub trait UintExp: Sized {
    /// Returns an upper bound for the highest bit set.
    /// Ideally this should not depend on the value.
    fn bit_len(&self) -> usize;

    /// Is the `indext`th bit set in the binary expansion of `self`.
    fn bit_ct(&self, index: usize) -> Choice;
}

/// Trait for ModRing parameter references.
///
/// Making this a trait allows both zero-sized and references to be used, so the same
/// implementation can cover both compile-time and runtime known fields. In the latter case,
/// a sufficiently large `Uint` will have to be picked compile time though.
pub trait RingRef: Copy + Deref<Target = ModRing<Self::Uint>> {
    type Uint: UintMont;
}

#[allow(clippy::wrong_self_convention)] // TODO: Do we want this?
pub trait RingRefExt: RingRef {
    fn from_montgomery(self, value: Self::Uint) -> ModRingElement<Self>;
    fn from<T: Into<Self::Uint>>(self, value: T) -> ModRingElement<Self>;
    fn zero(self) -> ModRingElement<Self>;
    fn one(self) -> ModRingElement<Self>;
}

/// Ring of integers modulo an odd positive integer.
/// TODO: Support even positive integers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ModRing<Uint: UintMont> {
    modulus: Uint,

    // Precomputed values for Montgomery multiplication.
    montgomery_r: Uint,  // R = 2^64*LIMBS mod modulus
    montgomery_r2: Uint, // R^2, or R in Montgomery form
    montgomery_r3: Uint, // R^3, or R^2 in Montgomery form
    mod_inv: u64,        // -1 / modulus mod 2^64
}

/// Element of a [`ModRing`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModRingElement<Ring: RingRef> {
    ring: Ring,
    value: Ring::Uint,
}

/// ModRingElement with the ring parameters by embedded reference.
pub type ModRingElementRef<'a, Uint> = ModRingElement<&'a ModRing<Uint>>;

impl<Uint: UintMont> RingRef for &ModRing<Uint> {
    type Uint = Uint;
}

impl<Uint: UintMont> ModRing<Uint> {
    pub fn from_modulus(modulus: Uint) -> Self {
        Uint::parameters_from_modulus(modulus)
    }

    pub fn modulus(&self) -> Uint {
        self.modulus
    }

    /// Montogomery multiplication for the ring.
    fn mont_mul(&self, a: Uint, b: Uint) -> Uint {
        a.mul_redc(b, self.modulus, self.mod_inv)
    }
}

impl<Ring: RingRef> RingRefExt for Ring {
    fn from_montgomery(self, value: Ring::Uint) -> ModRingElement<Self> {
        debug_assert!(value < self.modulus);
        ModRingElement { ring: self, value }
    }

    fn from<T: Into<Self::Uint>>(self, value: T) -> ModRingElement<Self> {
        let value = value.into();
        assert!(value < self.modulus);
        let value = self.mont_mul(value, self.montgomery_r2);
        self.from_montgomery(value)
    }

    fn zero(self) -> ModRingElement<Self> {
        self.from_montgomery(Ring::Uint::zero())
    }

    fn one(self) -> ModRingElement<Self> {
        self.from_montgomery(self.montgomery_r)
    }
}

impl<Ring: RingRef> ModRingElement<Ring> {
    pub fn ring(&self) -> &ModRing<Ring::Uint> {
        &self.ring
    }

    pub fn as_montgomery(self) -> Ring::Uint {
        self.value
    }

    pub fn to_uint(self) -> Ring::Uint {
        self.ring.mont_mul(self.value, Ring::Uint::one())
    }

    /// Small exponentiation
    ///
    /// Run time may depend on the exponent, use [`pow_ct`] if constant time is required.
    pub fn pow(self, exponent: u64) -> Self {
        match exponent {
            0 => self.ring.one(),
            1 => self,
            2 => self * self,
            3 => self * self * self,
            n if n % 4 == 0 => self.pow(n / 4),
            n => self.pow(n % 4) * self.pow(n / 4),
        }
    }

    /// Inversion
    ///
    /// Run time may depend on the value.
    pub fn inv(self) -> Option<Self> {
        let value = self.value.inv_mod(self.ring.modulus)?;
        let value = self.ring.mont_mul(value, self.ring.montgomery_r3);
        Some(self.ring.from_montgomery(value))
    }
}

impl<Ring: RingRef> ModRingElement<Ring>
where
    Ring::Uint: ConditionallySelectable,
{
    /// Constant-time exponentation with arbitrary unsigned int exponent.
    pub fn pow_ct<U: UintExp + Debug>(self, exponent: U) -> Self {
        dbg!(self, &exponent);
        let mut result = self.ring.one();
        let mut power = self;
        // We use `bit_len` here as an optimization when B >> log_2 exponent.
        // However, this does result in leaking the number of leading zeros.
        for i in 0..exponent.bit_len() {
            let product = result * power;
            result.conditional_assign(&product, exponent.bit_ct(i));
            power *= power;
        }
        dbg!(result);
        let value = result.value;
        self.ring.from_montgomery(value)
    }
}

macro_rules! forward_fmt {
    ($($trait:path),+) => {
        $(
            impl<Ring: RingRef> $trait for ModRingElement<Ring> where Ring::Uint: $trait {
                fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                    let uint = self.to_uint();
                    <Ring::Uint as $trait>::fmt(&uint, f)
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

impl<Ring: RingRef> Add for ModRingElement<Ring> {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self += other;
        self
    }
}

impl<Ring: RingRef> Sub for ModRingElement<Ring> {
    type Output = Self;

    fn sub(mut self, other: Self) -> Self {
        self -= other;
        self
    }
}

impl<Ring: RingRef> Mul for ModRingElement<Ring> {
    type Output = Self;

    fn mul(mut self, other: Self) -> Self {
        self *= other;
        self
    }
}

impl<Ring: RingRef> Neg for ModRingElement<Ring> {
    type Output = Self;

    fn neg(self) -> Self {
        // TODO: Constant time
        if self.value.is_zero() {
            self
        } else {
            let value = self.ring.modulus - self.value;
            self.ring.from_montgomery(value)
        }
    }
}

impl<Ring: RingRef> Div for ModRingElement<Ring> {
    type Output = Option<Self>;

    /// Division
    ///
    /// Run time may depend on the value of the divisor.
    fn div(self, other: Self) -> Option<Self> {
        assert_eq!(self.ring(), other.ring());
        other.inv().map(|inv| self * inv)
    }
}

impl<Ring: RingRef> AddAssign for ModRingElement<Ring> {
    fn add_assign(&mut self, other: Self) {
        assert_eq!(self.ring(), other.ring());
        self.value = self.value.add_mod(other.value, self.ring.modulus);
    }
}

impl<Ring: RingRef> SubAssign for ModRingElement<Ring> {
    fn sub_assign(&mut self, other: Self) {
        self.add_assign(other.neg())
    }
}

impl<Ring: RingRef> MulAssign for ModRingElement<Ring> {
    fn mul_assign(&mut self, other: Self) {
        assert_eq!(self.ring(), other.ring());
        self.value = self.ring.mont_mul(self.value, other.value);
    }
}

impl<Ring: RingRef> ConditionallySelectable for ModRingElement<Ring>
where
    Ring::Uint: ConditionallySelectable,
{
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        assert_eq!(a.ring(), b.ring());
        let value = Ring::Uint::conditional_select(&a.value, &b.value, choice);
        a.ring.from_montgomery(value)
    }
}

impl<Ring: RingRef> ConstantTimeEq for ModRingElement<Ring>
where
    Ring::Uint: ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        assert_eq!(self.ring(), other.ring());
        self.value.ct_eq(&other.value)
    }
}

impl<T> UintExp for T
where
    T: PrimInt + Unsigned + ConstantTimeEq + Debug,
{
    fn bit_len(&self) -> usize {
        T::zero().count_zeros() as usize
    }

    fn bit_ct(&self, index: usize) -> Choice {
        let bit = T::one() << index;
        (*self & bit).ct_eq(&bit)
    }
}
