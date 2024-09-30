use {
    super::{parse_uint, parse_uint_ref, EcParameters, PrimeField, ID_PRIME_FIELD},
    anyhow::{bail, ensure, Result},
    der::asn1::IntRef,
    ruint::aliases::U320,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EllipticCurve {
    pub base_field: PrimeField,
    pub scalar_field: PrimeField,
    pub a: U320,
    pub b: U320,
    pub cofactor: U320,
    pub generator: (U320, U320),
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
        let base_field = PrimeField::new(modulus);

        let order = parse_uint(&params.order)?;
        // ensure!(is_prime(&order));
        ensure!(order != modulus);
        let scalar_field = PrimeField::new(order);

        let cofactor = (params.cofactor)
            .as_ref()
            .map(parse_uint)
            .transpose()?
            .unwrap_or(U320::from(1));

        // Read curve parameters (TR-03111 section 2.3.1)
        let a = base_field.os2fe(params.curve.a.as_bytes());
        let b = base_field.os2fe(params.curve.b.as_bytes());

        // Check non-singualr requirement 4a^3 + 27b^2 != 0
        let mut check_a = base_field.pow(a, U320::from(3));
        check_a = base_field.mul(check_a, U320::from(4));
        let mut check_b = base_field.pow(b, U320::from(2));
        check_b = base_field.mul(check_b, U320::from(27));
        ensure!(base_field.add(check_a, check_b) != U320::ZERO);

        let mut curve = Self {
            base_field,
            scalar_field,
            a,
            b,
            cofactor,
            generator: (U320::ZERO, U320::ZERO),
        };
        curve.generator = curve.parse_point(params.base.as_bytes())?;
        Ok(curve)
    }

    pub fn ensure_valid(&self, (x, y): (U320, U320)) -> Result<()> {
        let lhs = self.base_field.pow(y, U320::from(2));
        let mut rhs = self.base_field.pow(x, U320::from(3));
        rhs = self.base_field.add(rhs, self.base_field.mul(self.a, x));
        rhs = self.base_field.add(rhs, self.b);
        ensure!(lhs == rhs, "Point not on curve.");

        if self.cofactor != U320::from(1) {
            // TODO: Check cofactor. self.order * point == infty
            bail!("Cofactor check unimplemented")
        }
        Ok(())
    }

    pub fn parse_point(&self, bytes: &[u8]) -> Result<(U320, U320)> {
        ensure!(!bytes.is_empty());
        let fe_len = self.base_field.modulus.byte_len();
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
