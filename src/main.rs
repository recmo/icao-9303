#![allow(dead_code)]

mod crypto;
mod icao9303;
mod iso7816;
mod nfc;

use {
    crate::{icao9303::Icao9303, nfc::Nfc},
    anyhow::Result,
    der::{
        asn1::{AnyRef, ObjectIdentifier},
        Sequence, ValueOrd,
    },
    hex_literal::hex,
    std::env,
};

#[repr(u16)]
pub enum File {
    //
    MasterFile = 0x3F00,
    Directory = 0x2F00,
    Attributes = 0x2F01,

    // ICAO 9303-10
    CardAccess = 0x011C,
    CardSecurity = 0x011D,
}

/// ICAO 9303 9.2 `SecurityInfo`
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SecurityInfo<'a> {
    protocol: ObjectIdentifier,
    required_data: AnyRef<'a>,
    optional_data: Option<AnyRef<'a>>,
}

pub const MY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.127.0.7.2.2.4.2.4");

fn main() -> Result<()> {
    // Find and open the Proxmark3 device
    let mut nfc = Nfc::new_proxmark3()?;

    // TODO: Implement full ICAO-9303-4.2 Chip Access Procedure.

    // Connect to ISO 14443-A card as reader, keeping the field on.
    nfc.connect()?;
    let mut card = Icao9303::new(nfc);

    println!("=== Card capabilities");
    card.send_apdu(&hex!("00CA 5F52 0F"))?;
    card.send_apdu(&hex!("00CA 5F51 20"))?;
    card.send_apdu(&hex!("00CA 0061 00"))?;

    // 0a 78f7b10280738421406714

    // See ICAO 9303-10 figure 3 for file structure.

    // Read CardAccess file using short EF.
    // Presence means PACE is supported.
    println!("=== Select master file.");
    card.select_master_file()?;
    println!("=== Read CardAccess.");
    let data = card.read_binary_short_ef(0x1C)?;
    println!("CardAccess: {}", hex::encode(data));

    println!("=== Basic Access Control.");
    let mut rng = rand::thread_rng();
    let mrz = env::var("MRZ")?;
    card.basic_access_control(&mut rng, &mrz)?;

    // Should be secured now!
    println!("=== Master File.");
    card.select_master_file()?;
    if let Ok(data) = card.read_binary_short_ef(0x01) {
        println!("==> EF.ATTR: {}", hex::encode(data));
    }
    if let Ok(data) = card.read_binary_short_ef(0x1C) {
        println!("==> CardAccess: {}", hex::encode(data));
    }
    if let Ok(data) = card.read_binary_short_ef(0x1D) {
        println!("==> CardSecurity: {}", hex::encode(data));
    }
    if let Ok(data) = card.read_binary_short_ef(0x1E) {
        println!("==> EF.DIR: {}", hex::encode(data));
    }

    // Select LDS1 eMRTD Application
    println!("=== LDS1 eMRTD Application.");
    card.select_dedicated_file(&hex!("A0000002471001"))?;
    if let Ok(data) = card.read_binary_short_ef(0x1E) {
        // EF.COM is a mandatory file.
        // This will contain a list of data groups that are present.
        println!("==> EF.COM: ({} B) {}", data.len(), hex::encode(data));
    }
    if let Ok(data) = card.read_binary_short_ef(0x01) {
        println!("==> EF.DG1: ({} B) {}", data.len(), hex::encode(data));
    }
    // if let Ok(data) = card.read_binary_short_ef(0x03) {
    //     // Finger print, not allowed to read.
    //     println!("==> EF.DG3: ({} B) {}", data.len(), hex::encode(data));
    // }
    // if let Ok(data) = card.read_binary_short_ef(0x0E) {
    //     println!("==> EF.DG14: ({} B) {}", data.len(), hex::encode(data));
    // }
    // if let Ok(data) = card.read_binary_short_ef(0x0F) {
    //     println!("==> EF.DG15: {}", hex::encode(data));
    // }
    // if let Ok(data) = card.read_binary_short_ef(0x10) {
    //     println!("==> EF.DG16: {}", hex::encode(data));
    // }
    // if let Ok(data) = card.read_binary_short_ef(0x1D) {
    //     println!("==> EF.SOD: {}", hex::encode(data));
    // }
    // 60 18  5f0104 30313037 5f3606 303430303030 5c06 61 75 6c 6f 63 6e // DG1 DG2 DG12 DG15 DG3  DG14

    // Active Authentication with fixed nonce
    // ICAO 9303-11 section 6.1
    eprintln!("=== Active Authentication");
    let (_status, data) = card.send_apdu(&hex!("00 88 0000  08  00 01 02 03 04 05 06 07  00"))?;
    println!("==> Active Authentication: {}", hex::encode(data));

    // Chip Authentication
    // ICAO 9303-11 section 6.2
    eprintln!("=== Chip Authentication");
    let (_status, data) = card.send_apdu(&hex!("00 22 41A6  08  00 01 02 03 04 05 06 07  00"))?;
    println!("==> Active Authentication: {}", hex::encode(data));

    Ok(())
}
