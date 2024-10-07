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
    der::Decode,
    icao9303::{
        asn1::{EfCardAccess, EfDg14, EfSod},
        Error, FileId,
    },
    iso7816::StatusWord,
    std::env,
};

// https://github.com/RfidResearchGroup/proxmark3/issues/1117

fn main() -> Result<()> {
    let mut rng = rand::thread_rng();

    let ef_sod = EfSod::from_der(include_bytes!("../dump/EF_SOD.bin"))?;
    println!("DOCUMENT HASH = 0x{}", hex::encode(ef_sod.document_hash()));

    let ef_card_access = EfCardAccess::from_der(include_bytes!("../dump/EF_CardAccess.bin"))?;
    println!(
        "EF_CardAccess: {}",
        hex::encode(include_bytes!("../dump/EF_CardAccess.bin"))
    );
    println!("EF.CardAccess: {:?}", ef_card_access);

    println!(
        "EF_DG14: {}",
        hex::encode(include_bytes!("../dump/EF_DG14.bin"))
    );
    let ef_ddg_14 = EfDg14::from_der(include_bytes!("../dump/EF_DG14.bin"))?;
    println!("EF.DG14: {:?}", ef_ddg_14);

    return Ok(());

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
    println!("DOCUMENT HASH = 0x{}", hex::encode(sod.document_hash()));

    // Do Chip Authentication
    card.chip_authenticate(&mut rng)?;

    Ok(())
}
