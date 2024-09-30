use ruint::aliases::U320;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PrimeField {
    pub modulus: U320,
}

impl PrimeField {
    pub fn new(modulus: U320) -> Self {
        Self { modulus }
    }

    /// Implements TR-03111 section 3.1.3 OS2FE procedure.
    ///
    /// Note that it does not have any requirement on the input length and requires
    /// the reader to apply the modular reduction. Note that this violates the unique
    /// encoding property of DER encoding, but we'll apply the robustness principle and
    /// allow it.
    ///
    /// The matching encoding procedure, however, does specify an exact length.
    pub fn os2fe(&self, os: &[u8]) -> U320 {
        if os.len() != self.modulus.byte_len() {
            eprintln!("Warning: OS2FE input length does not match modulus length")
        }

        let mut result = U320::ZERO;
        for byte in os {
            let byte = U320::from(*byte);
            result = result.mul_mod(U320::from(256), self.modulus); // Need reduction here as it can overflow.
            result = result.add_mod(byte, self.modulus);
        }
        result
    }

    pub fn add(&self, a: U320, b: U320) -> U320 {
        assert!(a < self.modulus);
        assert!(b < self.modulus);
        a.add_mod(b, self.modulus)
    }

    pub fn sub(&self, a: U320, b: U320) -> U320 {
        assert!(a < self.modulus);
        assert!(b < self.modulus);
        a.add_mod(self.neg(b), self.modulus)
    }

    pub fn mul(&self, a: U320, b: U320) -> U320 {
        assert!(a < self.modulus);
        assert!(b < self.modulus);
        a.mul_mod(b, self.modulus)
    }

    pub fn inv(&self, a: U320) -> Option<U320> {
        assert!(a < self.modulus);
        a.inv_mod(self.modulus)
    }

    pub fn div(&self, a: U320, b: U320) -> Option<U320> {
        assert!(a < self.modulus);
        assert!(b < self.modulus);
        b.inv_mod(self.modulus)
            .map(|inv_b| a.mul_mod(inv_b, self.modulus))
    }

    pub fn neg(&self, a: U320) -> U320 {
        assert!(a < self.modulus);
        self.modulus - a
    }

    pub fn pow(&self, a: U320, b: U320) -> U320 {
        assert!(a < self.modulus);
        a.pow_mod(b, self.modulus)
    }
}
