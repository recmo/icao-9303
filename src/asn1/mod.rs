//! Pure ASN1 types, no application logic.
//!
//! Parsing is done as deeply, for example a `SecurityInfo` is parsed into an enum
//! of the known OIDs with a catch-all for unimplemented cases. This ensures that rich types
//! are available for the application to use, but still allows for parsing of all valid inputs.
//!
//! A second goal is for the parsing to be exactly reversible. In this is guaranteed by DER,
//! but unfortunately real world data is not always DER compliant, or the standard is ambiguous.
//! In this case we take care to store the details of the input, so that the output can be
//! exactly reconstructed. See for example the [`DigestAlgorithmIdentifier`] parameters (which
//! have two wayss of encoding 'no parameters') and [`OrderedSet`].

mod application_tagged;
mod content_info;
mod digest_algorithm_identifier;
mod ordered_set;
pub mod public_key;
pub mod security_info;

pub use self::{
    application_tagged::ApplicationTagged,
    content_info::{ContentInfo, ContentType},
    digest_algorithm_identifier::DigestAlgorithmIdentifier,
};
use {
    self::security_info::{
        ChipAuthenticationInfo, ChipAuthenticationPublicKeyInfo, SecurityInfo, SecurityInfos,
    },
    crate::ensure_err,
    cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfo},
    der::{
        asn1::{ObjectIdentifier as Oid, OctetString, PrintableString},
        Any, Decode, Error, ErrorKind, Length, Result, Sequence, Tag, ValueOrd,
    },
};

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AnyAlgorithmIdentifier {
    pub algorithm: Oid,
    pub parameters: Option<Any>,
}

impl ContentType for SignedData {
    const CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
}

/// EF_CardAccess is a [`SecurityInfos`] with no further wrapping.
///
/// See ICAO-9303-10 3.11.3
pub type EfCardAccess = SecurityInfos;

/// EF_DG14 is a [`SecurityInfos`] with no further wrapping.
///
/// See ICAO-9303-10 3.11.4
pub type EfDg14 = ApplicationTagged<14, SecurityInfos>;

/// EF_SOD is a wrapped [`SignedData`] structure.
///
/// See ICAO-9303-10 4.7.14. The 0x6E tag is an ASN1 Application
/// constructed application tag with the value 14.
pub type EfSod = ApplicationTagged<23, ContentInfo<SignedData>>;

/// ICAO-9303-10 4.6.2.3
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct LdsSecurityObject {
    pub version: u64,
    pub hash_algorithm: DigestAlgorithmIdentifier,
    pub data_group_hash_values: Vec<DataGroupHash>,
    pub lds_version_info: Option<LdsVersionInfo>,
}

/// ICAO-9303-10 4.6.2.3
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct LdsVersionInfo {
    pub lds_version: PrintableString,
    pub unicode_version: PrintableString,
}

/// ICAO-9303-10 4.6.2.3
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct DataGroupHash {
    pub data_group_number: u64,
    pub hash_value: OctetString,
}

impl ContentType for LdsSecurityObject {
    /// ICAO-9303-10 4.6.2.3
    const CONTENT_TYPE: Oid = Oid::new_unwrap("2.23.136.1.1.1");
}

impl EfDg14 {
    pub fn chip_authentication(
        &self,
    ) -> Option<(&ChipAuthenticationInfo, &ChipAuthenticationPublicKeyInfo)> {
        // For now, we take the first ChipAuthentication and ChipAuthenticationPublicKey.
        let ca = self.0.iter().find_map(|si| match si {
            SecurityInfo::ChipAuthentication(ca) => Some(ca),
            _ => None,
        })?;
        // Find the corresponding ChipAuthenticationPublicKey based on key id (could both be None)
        let capk = self.0.iter().find_map(|si| match si {
            SecurityInfo::ChipAuthenticationPublicKey(capk) if capk.key_id == ca.key_id => {
                Some(capk)
            }
            _ => None,
        })?;
        Some((ca, capk))
    }
}

impl EfSod {
    pub fn signed_data(&self) -> &SignedData {
        &self.0 .0
    }

    pub fn signer_info(&self) -> &SignerInfo {
        // TODO: Handle errors
        self.signed_data()
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("missing signer info")
    }

    pub fn signature(&self) -> &[u8] {
        self.signer_info().signature.as_bytes()
    }

    /// Returns the Blake3 hash of the document signature
    pub fn document_hash(&self) -> [u8; 32] {
        *blake3::hash(self.signature()).as_bytes()
    }

    pub fn encapsulated_content(&self) -> &EncapsulatedContentInfo {
        &self.signed_data().encap_content_info
    }

    pub fn lds_security_object(&self) -> Result<LdsSecurityObject> {
        let econ = self.encapsulated_content();
        ensure_err!(
            econ.econtent_type == LdsSecurityObject::CONTENT_TYPE,
            Error::new(
                ErrorKind::OidUnknown {
                    oid: econ.econtent_type
                },
                Length::ZERO,
            )
        );
        let octet_string = econ
            .econtent
            .as_ref()
            .ok_or(Error::new(
                ErrorKind::TagUnexpected {
                    expected: Some(Tag::OctetString),
                    actual: Tag::Null, // Actually None
                },
                Length::ZERO,
            ))?
            .decode_as::<OctetString>()?;
        LdsSecurityObject::from_der(octet_string.as_bytes())
    }
}

impl LdsSecurityObject {
    pub fn hash_for_dg(&self, dg_number: usize) -> Option<&[u8]> {
        for entry in &self.data_group_hash_values {
            if entry.data_group_number == dg_number as u64 {
                return Some(entry.hash_value.as_bytes());
            }
        }
        None
    }
}
