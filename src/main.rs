#![allow(dead_code)]

mod icao9303;
mod iso7816;
mod nfc;
mod tr03110;
mod tr03111;

use {
    crate::{
        icao9303::{Icao9303, SecurityInfo},
        nfc::connect_reader,
    },
    anyhow::{anyhow, ensure, Result},
    der::{
        asn1::{AnyRef, SetOfVec},
        Decode, Tagged,
    },
    hex_literal::hex,
    icao9303::secure_messaging::{aes::Aes256Cipher, Encrypted},
    std::env,
    tr03110::{oid_name, ChipAuthenticationInfo, ChipAuthenticationPublicKeyInfo},
    tr03111::{ecka, ECAlgoParameters, EllipticCurve, ID_EC_PUBLIC_KEY},
};

// https://github.com/RfidResearchGroup/proxmark3/issues/1117

fn main() -> Result<()> {
    // TODO: Some passports only have ChipAuthenticationPublicKeyInfo but no ChipAuthenticationInfo. In this case, CA_(EC)DH_3DES_CBC_CBC should be assumed.

    // My eMRTD uses BrainpoolP320R1, but instead of providing a named curve it has explicit parameters!

    // Find and open the Proxmark3 device
    let mut nfc = connect_reader()?;

    // TODO: Implement full ICAO-9303-4.2 Chip Access Procedure.

    // Connect to ISO 14443-A card as reader, keeping the field on.
    nfc.connect()?;
    let mut card = Icao9303::new(nfc);

    // println!("=== Card capabilities");
    // card.send_apdu(&hex!("00CA 5F52 0F"))?;
    // card.send_apdu(&hex!("00CA 5F51 20"))?;
    // card.send_apdu(&hex!("00CA 0061 00"))?;

    // See ICAO 9303-10 figure 3 for file structure.

    // Read CardAccess file using short EF.
    // Presence means PACE is supported.
    println!("=== Select master file.");
    card.select_master_file()?;
    println!("=== Read CardAccess.");
    let data = card.read_file(0x1C)?;
    println!("CardAccess: {}", hex::encode(data));

    println!("=== Basic Access Control.");
    let mut rng = rand::thread_rng();
    let mrz = env::var("MRZ")?;
    card.basic_access_control(&mut rng, &mrz)?;

    // Should be secured now!
    println!("=== Master File.");
    card.select_master_file()?;
    if let Ok(data) = card.read_file(0x01) {
        println!("==> EF.ATTR: {}", hex::encode(data));
    }
    if let Ok(data) = card.read_file(0x1C) {
        println!("==> CardAccess: {}", hex::encode(data));
    }
    if let Ok(data) = card.read_file(0x1D) {
        println!("==> CardSecurity: {}", hex::encode(data));
    }
    if let Ok(data) = card.read_file(0x1E) {
        println!("==> EF.DIR: {}", hex::encode(data));
    }

    // Select LDS1 eMRTD Application
    println!("=== LDS1 eMRTD Application.");
    card.select_dedicated_file(&hex!("A0000002471001"))?;
    if let Ok(data) = card.read_file(0x1E) {
        // EF.COM is a mandatory file.
        // This will contain a list of data groups that are present.
        println!("==> EF.COM: ({} B) {}", data.len(), hex::encode(data));
    }
    // if let Ok(data) = card.read_file(0x01) {
    //     println!("==> EF.DG1: ({} B) {}", data.len(), hex::encode(data));
    // }
    // if let Ok(data) = card.read_file(0x02) {
    //     println!("==> EF.DG2: ({} B) {}", data.len(), hex::encode(data));
    // }
    // if let Ok(data) = card.read_file(0x03) {
    //     // Finger print, not allowed to read.
    //     println!("==> EF.DG3: ({} B) {}", data.len(), hex::encode(data));
    // }
    if let Ok(data) = card.read_file(0x0E) {
        println!("==> EF.DG14: ({} B) {}", data.len(), hex::encode(data));
    }
    if let Ok(data) = card.read_file(0x0F) {
        println!("==> EF.DG15: ({} B) {}", data.len(), hex::encode(data));
    }
    if let Ok(data) = card.read_file(0x10) {
        println!("==> EF.DG16: ({} B) {}", data.len(), hex::encode(data));
    }
    if let Ok(data) = card.read_file(0x1D) {
        println!("==> EF.SOD: ({} B) {}", data.len(), hex::encode(data));
    }

    // Active Authentication with fixed nonce
    // ICAO 9303-11 section 6.1
    eprintln!("=== Active Authentication");
    let (_status, data) = card.send_apdu(&hex!("00 88 0000  08  00 01 02 03 04 05 06 07  00"))?;
    println!("==> Active Authentication: {}", hex::encode(data));

    // Chip Authentication
    // ICAO 9303-11 section 6.2
    eprintln!("=== Chip Authentication");
    let ef_dg14 = card.read_file(0x0E)?;
    println!("EF_DG14 = {}", hex::encode(&ef_dg14));

    // let (_status, data) = card.send_apdu(&hex!("00 22 41A6  08  00 01 02 03 04 05 06 07  00"))?;
    // println!("==> Active Authentication: {}", hex::encode(data));

    // let ef_dg14 = include_bytes!("../dump/EF_DG14.bin").to_vec();

    let tagged = AnyRef::from_der(&ef_dg14)?;
    ensure!(tagged.tag() == 0x6E.try_into().unwrap());

    // Find the Chip Authentication Info
    let mut ca = None;
    let mut pk = None;
    for security_info in SetOfVec::<SecurityInfo>::from_der(tagged.value())?.iter() {
        dbg!(security_info.protocol, oid_name(security_info.protocol));
        if let Ok(found_ca) = ChipAuthenticationInfo::try_from(security_info) {
            ca = Some(found_ca);
        }
        if let Ok(found_pk) = ChipAuthenticationPublicKeyInfo::try_from(security_info) {
            pk = Some(found_pk);
        }
    }
    let ca = ca.ok_or_else(|| anyhow!("Chip Authentication Info not found"))?;
    let pk = pk.ok_or_else(|| anyhow!("Chip Authentication Public Key Info not found"))?;
    println!("Using algorithm: {}", ca.algorithm_name());

    ensure!(pk.chip_authentication_public_key.algorithm.algorithm == ID_EC_PUBLIC_KEY);
    let ec_params = match pk.chip_authentication_public_key.algorithm.parameters {
        ECAlgoParameters::EcParameters(ec_params) => ec_params,
        _ => return Err(anyhow!("Expected ECParameters")),
    };

    let curve = EllipticCurve::from_parameters(&ec_params)?;
    dbg!(curve);

    let card_public_key = pk
        .chip_authentication_public_key
        .subject_public_key
        .as_bytes()
        .unwrap();
    let card_public_key = curve.pt_from_bytes(card_public_key)?;
    dbg!(card_public_key);

    // Generate ephemeral keypair
    let mut rng = rand::thread_rng();
    let private_key = curve.scalar_field().random_nonzero(&mut rng);
    let public_key = private_key * curve.generator();
    dbg!(private_key);
    dbg!(public_key);

    let (s, z) = ecka(private_key, card_public_key)?;
    dbg!(&s, hex::encode(&z));

    // Initiate Chip Authentication
    // ICAO-9303-11 section 6.2
    // 2. The terminal sends the public key to the eMRTD.
    //
    // For AES we need to use 6.2.4.2

    // Send MSE Set AT to select the Chip Authentication protocol.
    card.mset_at(ca.protocol, pk.key_id)?;

    // Send the public key using general authenticate
    let data = card.general_authenticate(&public_key.to_bytes())?;
    println!("==> General Authenticate: {}", hex::encode(data));

    // Keys should now have been changed.
    let sm = Encrypted::new(Aes256Cipher::from_seed(&z), 0);
    card.set_secure_messaging(Box::new(sm));
    //

    // Test the new keys.
    card.select_master_file()?;

    card.select_dedicated_file(&hex!("A0000002471001"))?;
    if let Ok(data) = card.read_file(0x0F) {
        println!("==> EF.DG15: ({} B) {}", data.len(), hex::encode(data));
    }

    Ok(())
}
