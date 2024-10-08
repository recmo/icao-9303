#![allow(dead_code)]

mod icao9303;
mod iso7816;
mod nfc;
mod tr03111;
mod utils;

use {
    crate::{icao9303::Icao9303, nfc::connect_reader},
    anyhow::{anyhow, Context, Result},
    icao9303::{asn1::EfSod, Error, FileId},
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
    ensure_err!(card.is_some(), anyhow!("No card found."));
    dbg!(&card);

    let mut card = Icao9303::new(nfc);

    // println!("=== Basic Access Control.");
    let mrz = env::var("MRZ")?;
    card.basic_access_control(&mut rng, &mrz)
        .context("Error during Basic Access Control.")?;
    eprintln!("Basic Access Control successful.");

    // let ef_sod = card.read_cached::<EfSod>()?;
    // println!("DOCUMENT HASH = 0x{}", hex::encode(ef_sod.document_hash()));

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

    // TODO: Verify SOD.
    // https://github.com/worldcoin/nfc-uniqueness-service/blob/d907d9ef33826034665592685c1e24d25bdb1259/src/routes/v1/mod.rs#L102

    // Active Authentication with fixed nonce
    // // ICAO 9303-11 section 6.1
    // eprintln!("=== Active Authentication");
    // let (_status, data) = card.send_apdu(&hex!("00 88 0000  08  00 01 02 03 04 05 06 07  00"))?;
    // println!("==> Active Authentication: {}", hex::encode(data));

    // Dump SOD
    let sod: EfSod = card.read_cached()?;
    println!("DOCUMENT HASH = 0x{}", hex::encode(sod.document_hash()));

    // Do Chip Authentication
    card.chip_authenticate(&mut rng)
        .context("Error during Chip Authentication.")?;

    Ok(())
}
