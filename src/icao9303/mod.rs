mod bac;
mod chip_authentication;
mod files;
pub mod secure_messaging;

use {
    self::secure_messaging::{PlainText, SecureMessaging},
    crate::{iso7816::StatusWord, nfc::NfcReader},
    anyhow::Result,
    der::{asn1::ObjectIdentifier, AnyRef, Sequence, ValueOrd},
    sha1::{Digest, Sha1},
};

pub struct Icao9303 {
    nfc: Box<dyn NfcReader>,
    secure_messaging: Box<dyn SecureMessaging>,
    extended_length: bool,
}

/// ICAO 9303 9.2 `SecurityInfo`
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SecurityInfo<'a> {
    pub protocol: ObjectIdentifier,
    pub required_data: AnyRef<'a>,
    pub optional_data: Option<AnyRef<'a>>,
}

impl Icao9303 {
    pub fn new(nfc: Box<dyn NfcReader>) -> Self {
        Self {
            nfc,
            secure_messaging: Box::new(PlainText),
            extended_length: false,
        }
    }

    pub fn set_secure_messaging(&mut self, secure_messaging: Box<dyn SecureMessaging>) {
        self.secure_messaging = secure_messaging;
    }

    pub fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        println!("Sending APDU: {}", hex::encode(apdu));
        let protected_apdu = self.secure_messaging.enc_apdu(apdu)?;
        println!("Sending PAPDU: {}", hex::encode(&protected_apdu));
        let (status, data) = self.nfc.send_apdu(&protected_apdu)?;
        eprintln!("Status: {}", status);

        // TODO: On SM error card will revert to plain APDU. Check for SM error.
        let data = self.secure_messaging.dec_response(status, &data)?;
        println!("Status: {}", status);
        println!("Data: {}", hex::encode(&data));
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
