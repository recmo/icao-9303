mod application_tagged;
mod content_info;

use {
    application_tagged::ApplicationTagged,
    cms::signed_data::{SignedData, SignerInfo},
    content_info::{ContentInfo, ContentType},
    der::asn1::ObjectIdentifier as Oid,
};

impl ContentType for SignedData {
    const CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
}

/// EF_SOD Application tag 23 = tag 0x77 encoded and wrapped
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
