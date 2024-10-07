mod application_tagged;
mod content_info;
mod security_info;

use {
    self::{
        application_tagged::ApplicationTagged,
        content_info::{ContentInfo, ContentType},
        security_info::SecurityInfos,
    },
    cms::signed_data::{SignedData, SignerInfo},
    der::asn1::ObjectIdentifier as Oid,
};

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
}
