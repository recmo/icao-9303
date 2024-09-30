mod bac;
mod files;
mod secure_messaging;

use {
    self::secure_messaging::{PlainText, SecureMessaging},
    crate::{iso7816::StatusWord, nfc::NfcReader},
    anyhow::Result,
    der::{asn1::ObjectIdentifier, AnyRef, Sequence, ValueOrd},
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

    pub fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        // println!("Sending APDU: {}", hex::encode(apdu));
        let protected_apdu = self.secure_messaging.enc_apdu(apdu)?;
        let (status, data) = self.nfc.send_apdu(&protected_apdu)?;

        // TODO: On SM error card will revert to plain APDU.
        let data = self.secure_messaging.dec_response(status, &data)?;
        //println!("Status: {}", status);
        //println!("Data: {}", hex::encode(&data));
        Ok((status, data))
    }
}
