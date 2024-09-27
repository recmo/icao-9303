mod proxmark3;

use {crate::iso7816::StatusWord, anyhow::Result};

pub struct Nfc {
    reader: Box<dyn NfcReader>,
}

pub trait NfcReader {
    fn connect(&mut self) -> Result<()>;
    fn disconnect(&mut self) -> Result<()>;
    fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)>;
}

impl Nfc {
    pub fn new_proxmark3() -> Result<Self> {
        let reader = proxmark3::Proxmark3::new()?;
        Ok(Nfc {
            reader: Box::new(reader),
        })
    }

    pub fn connect(&mut self) -> Result<()> {
        self.reader.connect()
    }

    pub fn disconnect(&mut self) -> Result<()> {
        self.reader.disconnect()
    }

    pub fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        self.reader.send_apdu(apdu)

        // TODO: handle GET RESPONSE
        // TODO: handle
    }
}
