mod proxmark3;

use {crate::iso7816::StatusWord, anyhow::Result};

pub trait NfcReader {
    // TODO: Should return card info, and reader/card capabilities like extended length.
    fn connect(&mut self) -> Result<()>;
    fn disconnect(&mut self) -> Result<()>;
    fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)>;
}

pub fn connect_reader() -> Result<Box<dyn NfcReader>> {
    Ok(Box::new(proxmark3::Proxmark3::new()?))
}
