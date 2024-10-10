use {
    super::{
        parse_uint,
        prime_field::{PrimeFieldElement, Uint},
        PrimeField,
    },
    crate::asn1::public_key::{
        ECAlgoParameters, EcParameters, FieldId, PubkeyAlgorithmIdentifier, SubjectPublicKeyInfo,
    },
    anyhow::{bail, ensure, Result},
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
    // Ideally we would store as PrimeFieldElement, but that would require a reference
    // to the field which confuses the borrow checker.
    a_monty: Uint,
    b_monty: Uint,
    cofactor: Uint,
    generator_monty: (Uint, Uint),
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

pub type EcMonty = Option<(Uint, Uint)>;

impl EllipticCurve {
    pub fn from_algorithm(algo: &PubkeyAlgorithmIdentifier) -> Result<Self> {
        match algo {
            PubkeyAlgorithmIdentifier::Ec(ECAlgoParameters::EcParameters(params)) => {
                Self::from_parameters(params)
            }
            _ => bail!("Unsupported algorithm for elliptic curve"),
        }
    }

    // TODO: ISO 7816 format (see TR-03111 section 5.1.2)
    pub fn from_parameters(params: &EcParameters) -> Result<Self> {
        ensure!(params.version == 1);

        // TR-03111 only specifies prime field curves.
        // The alternatives would be binary fields and other extension fields.
        // The are some binary field elliptic curves, but they are considered deprecated.
        // I am not aware of any extension field curves in use, other than for ZK-friendliness.
        // ensure!(params.field_id.field_type == ID_PRIME_FIELD);

        // Construct the base and scalar fields.
        let base_field = PrimeField::from_field_id(&params.field_id)?;
        let scalar_field = PrimeField::from_modulus(parse_uint(&params.order)?);

        // Ensure they are different fields.
        ensure!(
            base_field != scalar_field,
            "Base and scalar fields must be different"
        );

        // Read the optional cofactor, default to 1.
        let cofactor = (params.cofactor)
            .as_ref()
            .map(parse_uint)
            .transpose()?
            .unwrap_or(Uint::from(1));

        // Read curve parameters (TR-03111 section 2.3.1)
        let a = base_field.os2fe(&params.curve.a);
        let b = base_field.os2fe(&params.curve.b);

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
            generator_monty: (Uint::ZERO, Uint::ZERO),
        };
        let generator = curve.pt_from_bytes(params.base.as_bytes())?;
        curve.generator_monty = generator.as_monty().unwrap();
        Ok(curve)
    }

    pub fn base_field(&self) -> &PrimeField {
        &self.base_field
    }

    pub fn scalar_field(&self) -> &PrimeField {
        &self.scalar_field
    }

    pub fn cofactor(&self) -> Uint {
        self.cofactor
    }

    pub fn a(&self) -> PrimeFieldElement {
        self.base_field.el_from_monty(self.a_monty)
    }

    pub fn b(&self) -> PrimeFieldElement {
        self.base_field.el_from_monty(self.b_monty)
    }

    pub fn generator(&self) -> EllipticCurvePoint {
        self.pt_from_monty(Some(self.generator_monty)).unwrap()
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

    pub fn pt_from_monty(&self, monty: EcMonty) -> Result<EllipticCurvePoint> {
        match monty {
            Some((x, y)) => self.pt_from_affine((
                self.base_field.el_from_monty(x),
                self.base_field.el_from_monty(y),
            )),
            None => Ok(self.pt_infinity()),
        }
    }

    /// TR-03111 section 3.2
    pub fn pt_from_bytes(&self, bytes: &[u8]) -> Result<EllipticCurvePoint> {
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
        if self.cofactor != Uint::from(1) {
            // TODO: Check cofactor. self.order * point == infty
            bail!("Cofactor check unimplemented")
        }
        Ok(())
    }
}

impl EllipticCurvePoint<'_> {
    pub fn from_pubkey(pubkey: &SubjectPublicKeyInfo) -> Result<(EllipticCurve, EcMonty)> {
        let curve = EllipticCurve::from_algorithm(&pubkey.algorithm)?;
        let point = curve.pt_from_bytes(&pubkey.subject_public_key.raw_bytes())?;
        let monty = point.as_monty();
        Ok((curve, monty))
    }

    pub fn curve(&self) -> &EllipticCurve {
        self.curve
    }

    /// TR-03111 section 3.2
    ///
    /// TODO: Compressed?
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.coordinates {
            Coordinates::Infinity => vec![0x00],
            Coordinates::Affine(x, y) => {
                let mut bytes = vec![0x04];
                bytes.extend_from_slice(&x.fe2os());
                bytes.extend_from_slice(&y.fe2os());
                bytes
            }
        }
    }

    pub fn as_monty(&self) -> EcMonty {
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

impl Mul<Uint> for EllipticCurvePoint<'_> {
    type Output = Self;

    /// TODO: Constant time algorithm.
    fn mul(self, mut scalar: Uint) -> Self::Output {
        let mut result = self.curve.pt_infinity();
        let mut base = self;
        while scalar != Uint::ZERO {
            if scalar.bit(0) {
                result += base;
            }
            base += base;
            scalar >>= 1;
        }
        result
    }
}

impl<'a> Mul<EllipticCurvePoint<'a>> for Uint {
    type Output = EllipticCurvePoint<'a>;

    fn mul(self, point: EllipticCurvePoint<'a>) -> Self::Output {
        point * self
    }
}

impl MulAssign<Uint> for EllipticCurvePoint<'_> {
    fn mul_assign(&mut self, scalar: Uint) {
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
