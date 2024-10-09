use {
    const_oid::db::rfc8284::JID,
    der::{
        asn1::{ObjectIdentifier as Oid, OctetString, PrintableString},
        Any, Decode, Encode, Error, ErrorKind, Length, Result, Sequence, Tag, ValueOrd,
    },
    sha1::Digest,
};

/// https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash
pub const ID_SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");
pub const ID_SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const ID_SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
pub const ID_SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");
pub const ID_SHA224: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.4");
pub const ID_SHA512_224: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.5");
pub const ID_SHA512_256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.6");

// pub const ID_SHA3_224: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.7");
// pub const ID_SHA3_256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.7");

/// ICAO 9303-10 9.1
/// RFC 3280 `AlgorithmIdentifier`
/// RFC 5280 `AlgorithmIdentifier`
/// This deviates from RFC 5280 by using `Any` for parameters
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AlgorithmIdentifier {
    pub algorithm: Oid,
    pub parameters: Option<Any>,
}

impl AlgorithmIdentifier {
    pub fn name(&self) -> &'static str {
        match self.algorithm {
            ID_SHA1 => "SHA1",
            ID_SHA256 => "SHA2-256",
            ID_SHA384 => "SHA2-384",
            ID_SHA512 => "SHA2-512",
            ID_SHA224 => "SHA2-224",
            ID_SHA512_224 => "SHA2-512-224",
            ID_SHA512_256 => "SHA2-512-256",
            _ => "UNKNOWN",
        }
    }

    pub fn is_hash(&self) -> bool {
        matches!(
            self.algorithm,
            ID_SHA1 | ID_SHA256 | ID_SHA384 | ID_SHA512 | ID_SHA224 | ID_SHA512_224 | ID_SHA512_256
        )
    }

    pub fn hash_bytes(&self, data: &[u8]) -> Vec<u8> {
        match self.algorithm {
            ID_SHA1 => hash::<sha1::Sha1>(data),
            ID_SHA256 => hash::<sha2::Sha256>(data),
            ID_SHA384 => hash::<sha2::Sha384>(data),
            ID_SHA512 => hash::<sha2::Sha512>(data),
            ID_SHA224 => hash::<sha2::Sha224>(data),
            ID_SHA512_224 => hash::<sha2::Sha512_224>(data),
            ID_SHA512_256 => hash::<sha2::Sha512_256>(data),
            _ => panic!(),
        }
    }

    pub fn hash_der<T: Encode>(&self, object: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        object.encode_to_vec(&mut bytes).unwrap();
        self.hash_bytes(&bytes)
    }
}

fn hash<D: Digest>(data: &[u8]) -> Vec<u8> {
    let mut hasher = D::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.to_vec()
}
