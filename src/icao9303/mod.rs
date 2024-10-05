pub mod asn1;
mod bac;
mod chip_authentication;
mod files;
pub mod secure_messaging;

pub use self::files::{DedicatedId, FileId};
use {
    self::secure_messaging::{PlainText, SecureMessaging},
    crate::{
        iso7816::{self, StatusWord},
        nfc::NfcReader,
    },
    der::{asn1::ObjectIdentifier, AnyRef, Sequence, ValueOrd},
    files::FileCache,
    sha1::{Digest, Sha1},
    thiserror::Error,
};

pub struct Icao9303 {
    /// NFC Reader connected to card.
    nfc: Box<dyn NfcReader>,

    /// Current Secure Messaging cipher.
    secure_messaging: Box<dyn SecureMessaging>,

    /// If true, extended length APDUs may be supported.
    extended_length: bool,

    /// Currently selected parent.
    parent: DedicatedId,

    /// Cache of files read from the card.
    file_cache: FileCache,
}

/// ICAO 9303 9.2 `SecurityInfo`
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SecurityInfo<'a> {
    pub protocol: ObjectIdentifier,
    pub required_data: AnyRef<'a>,
    pub optional_data: Option<AnyRef<'a>>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("NFC error: {0}")]
    NfcError(anyhow::Error),

    #[error("Response Status: {0}")]
    ErrorResponse(StatusWord),

    #[error("Secure Messaging failed (status: {0}).")]
    SecureMessagingError(StatusWord),

    #[error("Invalid APDU")]
    InvalidApdu(#[from] iso7816::Error),

    #[error("Response exceeds maximum length.")]
    ResponseTooLong,

    #[error("Secure Messasing Response incomplete or incorrect.")]
    SMResponseInvalid,

    #[error("Secure Messasing Response failed MAC.")]
    SMResponseMacFailed,

    #[error("Response data is unexpected.")]
    ResponseDataUnexpected,

    #[error("Invalid Application ID")]
    InvalidApplicationId,

    #[error("Invalid Short File ID")]
    InvalidShortFileId,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<StatusWord> for Error {
    fn from(status: StatusWord) -> Self {
        Error::ErrorResponse(status)
    }
}

impl Icao9303 {
    pub fn new(nfc: Box<dyn NfcReader>) -> Self {
        Self {
            nfc,
            secure_messaging: Box::new(PlainText),
            extended_length: false,

            // On Reset chip is always in master file.
            parent: DedicatedId::MasterFile,
            file_cache: FileCache::new(),
        }
    }

    pub fn set_secure_messaging(&mut self, secure_messaging: Box<dyn SecureMessaging>) {
        self.secure_messaging = secure_messaging;
    }

    pub fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        let protected_apdu = self.secure_messaging.enc_apdu(apdu)?;

        let (status, data) = self
            .nfc
            .send_apdu(&protected_apdu)
            .map_err(Error::NfcError)?;
        match status {
            StatusWord::SECURE_MESSAGING_INCORRECT | StatusWord::SECURE_MESSAGING_INCOMPLETE => {
                // Reset secure messaging.
                self.set_secure_messaging(Box::new(PlainText));

                return Err(Error::SecureMessagingError(status));
            }
            _ => {}
        }

        // TODO: On SM error card will revert to plain APDU. Check for SM error.
        let data = self.secure_messaging.dec_response(status, &data)?;

        Ok((status, data))
    }
}

pub fn pad(bytes: &mut Vec<u8>, block_size: usize) {
    bytes.push(0x80);
    bytes.resize(bytes.len().next_multiple_of(block_size), 0x00);
}

pub fn seed_from_mrz(mrz: &str) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(mrz.as_bytes());
    let hash = hasher.finalize();
    hash[0..16].try_into().unwrap()
}
