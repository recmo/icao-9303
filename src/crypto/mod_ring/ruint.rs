//! [`ruint`] backend for [`ModRing`]

use {
    super::{ModRing, UintMont},
    ruint::{aliases::U64, Uint},
};

impl<const BITS: usize, const LIMBS: usize> UintMont for Uint<BITS, LIMBS> {
    fn parameters_from_modulus(modulus: Self) -> ModRing<Self> {
        let mod_inv = U64::wrapping_from(modulus)
            .inv_ring()
            .expect("Modulus not an odd positive integer.")
            .wrapping_neg()
            .to();
        let montgomery_r = Self::from(2).pow_mod(Self::from(BITS), modulus);
        let montgomery_r2 = montgomery_r.mul_mod(montgomery_r, modulus);
        let montgomery_r3 = montgomery_r2.mul_mod(montgomery_r, modulus);
        ModRing {
            modulus,
            mod_inv,
            montgomery_r,
            montgomery_r2,
            montgomery_r3,
        }
    }

    fn mul_redc(self, other: Self, modulus: Self, mod_inv: u64) -> Self {
        Uint::mul_redc(self, other, modulus, mod_inv)
    }

    fn add_mod(self, other: Self, modulus: Self) -> Self {
        Uint::add_mod(self, other, modulus)
    }

    fn inv_mod(self, modulus: Self) -> Option<Self> {
        Uint::inv_mod(self, modulus)
    }
}

#[test]
fn test_impl_uint_exp() {
    use {super::UintExp, ruint::aliases::U256};
    fn ok<T: UintExp>() {}
    ok::<U256>();
}
