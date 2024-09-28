//! Secure Messaging

mod tdes;

pub use tdes::TDesSM;
use {crate::iso7816::StatusWord, anyhow::Result};

pub trait SecureMessaging {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
    fn dec_response(&mut self, status: StatusWord, resp: &[u8]) -> Result<Vec<u8>>;
}

/// Secure Messaging protocol that passes APDUs and responses as-is.
pub struct PlainText;

impl SecureMessaging for PlainText {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        Ok(apdu.to_vec())
    }

    fn dec_response(&mut self, _status: StatusWord, resp: &[u8]) -> Result<Vec<u8>> {
        Ok(resp.to_vec())
    }
}
