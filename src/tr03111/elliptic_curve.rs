use {
    super::{
        parse_uint, parse_uint_ref, prime_field::PrimeFieldElement, EcParameters, PrimeField,
        ID_PRIME_FIELD,
    },
    anyhow::{bail, ensure, Result},
    der::asn1::IntRef,
    ruint::aliases::U320,
    std::{
        fmt::{self, Debug, Formatter},
        ops::{Add, AddAssign, Mul, MulAssign, Neg},
    },
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EllipticCurve {
    base_field: PrimeField,
    scalar_field: PrimeField,
    // Curve parameters in Montgomery form.
    // Ideally we would store as PrimeFieldElement, but that would require a reference to the field and confuses the borrow checker.
    a_monty: U320,
    b_monty: U320,
    cofactor: U320,
    generator_monty: (U320, U320),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EllipticCurvePoint<'a> {
    curve: &'a EllipticCurve,
    coordinates: Coordinates<'a>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Coordinates<'a> {
    Infinity,
    Affine(PrimeFieldElement<'a>, PrimeFieldElement<'a>),
}

impl EllipticCurve {
    // TODO: ISO 7816 format (see TR-03111 section 5.1.2)
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
        curve.generator_monty = generator.as_monty().unwrap();
        Ok(curve)
    }

    pub fn base_field(&self) -> &PrimeField {
        &self.base_field
    }

    pub fn scalar_field(&self) -> &PrimeField {
        &self.scalar_field
    }

    pub fn cofactor(&self) -> U320 {
        self.cofactor
    }

    pub fn a(&self) -> PrimeFieldElement {
        self.base_field.el_from_monty(self.a_monty)
    }

    pub fn b(&self) -> PrimeFieldElement {
        self.base_field.el_from_monty(self.b_monty)
    }

    pub fn generator(&self) -> EllipticCurvePoint {
        self.pt_from_monty(self.generator_monty).unwrap()
    }

    pub fn pt_infinity(&self) -> EllipticCurvePoint {
        EllipticCurvePoint {
            curve: self,
            coordinates: Coordinates::Infinity,
        }
    }

    pub fn pt_from_affine<'a>(
        &'a self,
        (x, y): (PrimeFieldElement<'a>, PrimeFieldElement<'a>),
    ) -> Result<EllipticCurvePoint<'a>> {
        ensure!(x.field() == &self.base_field);
        ensure!(y.field() == &self.base_field);
        self.ensure_valid((x, y))?;
        Ok(EllipticCurvePoint {
            curve: self,
            coordinates: Coordinates::Affine(x, y),
        })
    }

    pub fn pt_from_monty(&self, (x, y): (U320, U320)) -> Result<EllipticCurvePoint> {
        self.pt_from_affine((
            self.base_field.el_from_monty(x),
            self.base_field.el_from_monty(y),
        ))
    }

    pub fn parse_point(&self, bytes: &[u8]) -> Result<EllipticCurvePoint> {
        ensure!(!bytes.is_empty());
        let fe_len = self.base_field.byte_len();
        match bytes[0] {
            0x00 => {
                ensure!(bytes.len() == 1);
                Ok(self.pt_infinity())
            }
            0x02 => unimplemented!("Compressed point with y'p = 0"),
            0x03 => unimplemented!("Compressed point with y'p = 1"),
            0x04 => {
                // Uncompressed point
                ensure!(bytes.len() == 1 + 2 * fe_len);
                let x = self.base_field.os2fe(&bytes[1..1 + fe_len]);
                let y = self.base_field.os2fe(&bytes[1 + fe_len..]);
                self.pt_from_affine((x, y))
            }
            _ => bail!("Invalid point encoding"),
        }
    }

    fn ensure_valid(&self, (x, y): (PrimeFieldElement, PrimeFieldElement)) -> Result<()> {
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
}

impl EllipticCurvePoint<'_> {
    pub fn curve(&self) -> &EllipticCurve {
        self.curve
    }

    pub fn as_monty(&self) -> Option<(U320, U320)> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(x, y) => Some((x.as_uint_monty(), y.as_uint_monty())),
        }
    }

    pub fn x(&self) -> Option<PrimeFieldElement> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(x, _) => Some(x),
        }
    }

    pub fn y(&self) -> Option<PrimeFieldElement> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(_, y) => Some(y),
        }
    }
}

macro_rules! forward_fmt {
    ($($type:ty),+) => {
        $(
            impl $type for EllipticCurvePoint<'_> {
                fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                    match self.coordinates {
                        Coordinates::Infinity => write!(f, "Infinity"),
                        Coordinates::Affine(x, y) => {
                            write!(f, "(")?;
                            <PrimeFieldElement as $type>::fmt(&x, f)?;
                            write!(f, ", ")?;
                            <PrimeFieldElement as $type>::fmt(&y, f)?;
                            write!(f, ")")
                        }
                    }
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

impl Add for EllipticCurvePoint<'_> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        assert_eq!(self.curve, other.curve);
        // TODO: Use constant time inversions
        match (self.coordinates, other.coordinates) {
            (Coordinates::Infinity, _) => other,
            (_, Coordinates::Infinity) => self,
            (Coordinates::Affine(x1, y1), Coordinates::Affine(x2, y2)) => {
                // https://hyperelliptic.org/EFD/g1p/auto-shortw.html
                if x1 == x2 {
                    if y1 == y2 {
                        // Point doubling
                        let lambda = (self.curve.base_field.el_from_u64(3) * x1.pow(2)
                            + self.curve.a())
                            / (self.curve.base_field.el_from_u64(2) * y1);
                        let lambda = lambda.unwrap();
                        let x3 = lambda.pow(2) - self.curve.base_field.el_from_u64(2) * x1;
                        let y3 = lambda * (x1 - x3) - y1;
                        EllipticCurvePoint {
                            curve: self.curve,
                            coordinates: Coordinates::Affine(x3, y3),
                        }
                    } else {
                        // Point at infinity
                        self.curve.pt_infinity()
                    }
                } else {
                    let lambda = (y2 - y1) / (x2 - x1);
                    let lambda = lambda.unwrap();
                    let x3 = lambda.pow(2) - x1 - x2;
                    let y3 = lambda * (x1 - x3) - y1;
                    self.curve.pt_from_affine((x3, y3)).unwrap()
                }
            }
        }
    }
}

impl AddAssign for EllipticCurvePoint<'_> {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Neg for EllipticCurvePoint<'_> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self.coordinates {
            Coordinates::Infinity => self,
            Coordinates::Affine(x, y) => EllipticCurvePoint {
                curve: self.curve,
                coordinates: Coordinates::Affine(x, -y),
            },
        }
    }
}

impl Mul<U320> for EllipticCurvePoint<'_> {
    type Output = Self;

    /// TODO: Constant time algorithm.
    fn mul(self, mut scalar: U320) -> Self::Output {
        let mut result = self.curve.pt_infinity();
        let mut base = self;
        while scalar != U320::ZERO {
            if scalar.bit(0) {
                result += base;
            }
            base += base;
            scalar >>= 1;
        }
        result
    }
}

impl<'a> Mul<EllipticCurvePoint<'a>> for U320 {
    type Output = EllipticCurvePoint<'a>;

    fn mul(self, point: EllipticCurvePoint<'a>) -> Self::Output {
        point * self
    }
}

impl MulAssign<U320> for EllipticCurvePoint<'_> {
    fn mul_assign(&mut self, scalar: U320) {
        *self = *self * scalar;
    }
}

impl<'a, 'b> Mul<PrimeFieldElement<'a>> for EllipticCurvePoint<'b> {
    type Output = Self;

    fn mul(self, scalar: PrimeFieldElement<'a>) -> Self::Output {
        self * scalar.to_uint()
    }
}

impl<'a, 'b> Mul<EllipticCurvePoint<'b>> for PrimeFieldElement<'a> {
    type Output = EllipticCurvePoint<'b>;

    fn mul(self, point: EllipticCurvePoint<'b>) -> Self::Output {
        point * self
    }
}

impl<'a, 'b> MulAssign<PrimeFieldElement<'a>> for EllipticCurvePoint<'b> {
    fn mul_assign(&mut self, scalar: PrimeFieldElement<'a>) {
        *self = *self * scalar;
    }
}
