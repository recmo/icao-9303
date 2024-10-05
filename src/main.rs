#![allow(dead_code)]

mod icao9303;
mod iso7816;
mod nfc;
mod tr03110;
mod tr03111;
mod utils;

use {
    crate::{icao9303::Icao9303, nfc::connect_reader},
    anyhow::Result,
    icao9303::{Error, FileId},
    iso7816::StatusWord,
    std::env,
};

// https://github.com/RfidResearchGroup/proxmark3/issues/1117

fn main() -> Result<()> {
    let mut rng = rand::thread_rng();

    // Find and open the Proxmark3 device
    let mut nfc = connect_reader()?;

    // Connect to ISO 14443-A card as reader, keeping the field on.
    let card = nfc.connect()?;
    dbg!(&card);
    assert!(card.is_some());

    let mut card = Icao9303::new(nfc);

    // println!("=== Basic Access Control.");
    let mrz = env::var("MRZ")?;
    card.basic_access_control(&mut rng, &mrz)?;
    eprintln!("Basic Access Control successful.");

    println!("=== Read SOD");
    dbg!(card.ef_sod()?);

    // Should be secured now!
    // Let's read some files.
    for file_id in FileId::iter() {
        match card.read_file_cached(file_id) {
            Ok(Some(data)) => println!("{}: {}", file_id, hex::encode(data)),
            Ok(None) => println!("{}: Not Found", file_id),
            Err(Error::ErrorResponse(StatusWord::ACCESS_DENIED)) => {
                println!("{}: Access Denied", file_id)
            }
            Err(e) => eprintln!("{}: {}", file_id, e),
        }
    }

    // Active Authentication with fixed nonce
    // // ICAO 9303-11 section 6.1
    // eprintln!("=== Active Authentication");
    // let (_status, data) = card.send_apdu(&hex!("00 88 0000  08  00 01 02 03 04 05 06 07  00"))?;
    // println!("==> Active Authentication: {}", hex::encode(data));

    // Dump SOD
    let sod = card.ef_sod()?;

    // Get Signature bytes
    let signature = sod.signer_infos.0.as_slice()[0].signature.as_bytes();

    // Hash of the signature bytes
    let hash = blake3::hash(signature);
    println!("DOCUMENT HASH = 0x{}", hex::encode(hash.as_bytes()));

    // Do Chip Authentication
    card.chip_authenticate(&mut rng)?;

    Ok(())
}
