mod bac;
mod files;
mod secure_messaging;

use {
    self::secure_messaging::{PlainText, SecureMessaging},
    crate::{iso7816::StatusWord, nfc::Nfc},
    anyhow::Result,
};

pub struct Icao9303 {
    nfc: Nfc,
    secure_messaging: Box<dyn SecureMessaging>,
}

impl Icao9303 {
    pub fn new(nfc: Nfc) -> Self {
        Self {
            nfc,
            secure_messaging: Box::new(PlainText),
        }
    }

    pub fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        let protected_apdu = self.secure_messaging.enc_apdu(apdu)?;
        let (status, data) = self.nfc.send_apdu(&protected_apdu)?;

        // TODO: On SM error card will revert to plain APDU.
        let data = self.secure_messaging.dec_response(status, &data)?;
        Ok((status, data))
    }
}
