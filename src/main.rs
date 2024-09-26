#![allow(dead_code)]

mod nfc;

use {
    crate::nfc::Nfc,
    anyhow::{ensure, Result},
};

fn main() -> Result<()> {
    // Find and open the Proxmark3 device
    let mut nfc = Nfc::new_proxmark3()?;

    // Connect to ISO 14443-A card as reader, keeping the field on.
    nfc.connect()?;

    // Select Master File (deprecated/unreliable way)
    let (status, data) = nfc.send_apdu(&[0x00, 0xA4, 0x00, 0x0C])?;
    ensure!(status == 0x9000);
    ensure!(data.is_empty());

    // Select Master File with explicit id (alternative way)
    let (status, data) = nfc.send_apdu(&[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])?;
    ensure!(status == 0x9000);
    ensure!(data.is_empty());

    // Select file
    // See ICAO 9303 Part 10, table 38.
    // Select EF.CardAccess (0x011C)
    let (status, data) = nfc.send_apdu(&[0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C])?;
    ensure!(status == 0x9000);
    ensure!(data.is_empty());

    // Read EF.CardAccess
    let (status, data) = nfc.send_apdu(&[0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0xFF])?;
    ensure!(status == 0x9000);

    // Switch field off and close the USB connection
    nfc.disconnect()?;
    Ok(())
}
