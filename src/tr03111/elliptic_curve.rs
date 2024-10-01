use {
    super::{
        parse_uint, parse_uint_ref, prime_field::PrimeFieldElement, EcParameters, PrimeField,
        ID_PRIME_FIELD,
    },
    anyhow::{bail, ensure, Result},
    der::asn1::IntRef,
    ruint::aliases::U320,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EllipticCurve {
    pub base_field: PrimeField,
    pub scalar_field: PrimeField,
    // Curve parameters in Montgomery form.
    // Ideally we would store as PrimeFieldElement, but that would require a reference to the field and confuses the borrow checker.
    a_monty: U320,
    b_monty: U320,
    pub cofactor: U320,
    generator_monty: (U320, U320),
}

impl EllipticCurve {
    pub fn from_parameters(params: &EcParameters) -> Result<Self> {
        ensure!(params.version == 1);

        // TR-03111 only specifies prime field curves.
        // The alternatives would be binary fields and other extension fields.
        // The are some binary field elliptic curves, but they are considered deprecated.
        // I am not aware of any extension field curves in use, other than for ZK-friendliness.
        ensure!(params.field_id.field_type == ID_PRIME_FIELD);

        // For a prime field the parameter is the prime modulus encoded as DER Integer.
        let modulus: IntRef = params.field_id.parameters.decode_as()?;
        let modulus = parse_uint_ref(modulus)?;
        // ensure!(is_prime(&modulus));
        let base_field = PrimeField::from_modulus(modulus);

        let order = parse_uint(&params.order)?;
        // ensure!(is_prime(&order));
        ensure!(order != modulus);
        let scalar_field = PrimeField::from_modulus(order);

        let cofactor = (params.cofactor)
            .as_ref()
            .map(parse_uint)
            .transpose()?
            .unwrap_or(U320::from(1));

        // Read curve parameters (TR-03111 section 2.3.1)
        let a = base_field.os2fe(params.curve.a.as_bytes());
        let b = base_field.os2fe(params.curve.b.as_bytes());

        // Check non-singular requirement 4a^3 + 27b^2 != 0
        ensure!(
            base_field.el_from_u64(4) * a.pow(3) + base_field.el_from_u64(27) * b.pow(2)
                != base_field.zero()
        );

        let mut curve = Self {
            base_field,
            scalar_field,
            a_monty: a.as_uint_monty(),
            b_monty: b.as_uint_monty(),
            cofactor,
            generator_monty: (U320::ZERO, U320::ZERO),
        };
        let generator = curve.parse_point(params.base.as_bytes())?;
        curve.generator_monty = (generator.0.as_uint_monty(), generator.1.as_uint_monty());
        Ok(curve)
    }

    pub fn a(&self) -> PrimeFieldElement {
        self.base_field.el_from_monty(self.a_monty)
    }

    pub fn b(&self) -> PrimeFieldElement {
        self.base_field.el_from_monty(self.b_monty)
    }

    pub fn generator(&self) -> (PrimeFieldElement, PrimeFieldElement) {
        (
            self.base_field.el_from_monty(self.generator_monty.0),
            self.base_field.el_from_monty(self.generator_monty.1),
        )
    }

    pub fn ensure_valid(&self, (x, y): (PrimeFieldElement, PrimeFieldElement)) -> Result<()> {
        // Check curve equation y^2 = x^3 + ax + b
        ensure!(
            y.pow(2) == x.pow(3) + self.a() * x + self.b(),
            "Point not on curve."
        );
        if self.cofactor != U320::from(1) {
            // TODO: Check cofactor. self.order * point == infty
            bail!("Cofactor check unimplemented")
        }
        Ok(())
    }

    pub fn parse_point(&self, bytes: &[u8]) -> Result<(PrimeFieldElement, PrimeFieldElement)> {
        ensure!(!bytes.is_empty());
        let fe_len = self.base_field.byte_len();
        let point = match bytes[0] {
            0x00 => unimplemented!("Point at infinity"),
            0x02 => unimplemented!("Compressed point with y'p = 0"),
            0x03 => unimplemented!("Compressed point with y'p = 1"),
            0x04 => {
                // Uncompressed point
                ensure!(bytes.len() == 1 + 2 * fe_len);
                let x = self.base_field.os2fe(&bytes[1..1 + fe_len]);
                let y = self.base_field.os2fe(&bytes[1 + fe_len..]);
                (x, y)
            }
            _ => bail!("Invalid point encoding"),
        };
        self.ensure_valid(point)?;
        Ok(point)
    }
}
