#![allow(dead_code)]

mod icao9303;
mod iso7816;
mod nfc;
mod tr03110;
mod tr03111;
mod utils;

use {
    crate::{
        icao9303::{Icao9303, SecurityInfo},
        nfc::connect_reader,
    },
    anyhow::{anyhow, ensure, Result},
    cms::{
        content_info::CmsVersion,
        revocation::RevocationInfoChoices,
        signed_data::{
            CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData,
            SignerInfos,
        },
    },
    der::{
        asn1::{AnyRef, ObjectIdentifier as Oid, SetOfVec},
        Any, Decode, DecodeValue, Encode, EncodeRef, EncodeValue, Sequence, SliceReader, Tag,
        Tagged,
    },
    hex_literal::hex,
    icao9303::{
        secure_messaging::{aes::Aes256Cipher, Encrypted, SymmetricCipher},
        Error, FileId,
    },
    iso7816::StatusWord,
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

    println!("=== Basic Access Control.");
    let mut rng = rand::thread_rng();
    let mrz = env::var("MRZ")?;
    card.basic_access_control(&mut rng, &mrz)?;

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
    // ICAO 9303-11 section 6.1
    eprintln!("=== Active Authentication");
    let (_status, data) = card.send_apdu(&hex!("00 88 0000  08  00 01 02 03 04 05 06 07  00"))?;
    println!("==> Active Authentication: {}", hex::encode(data));

    // Do Chip Authentication
    card.chip_authenticate(&mut rng)?;

    // Test the new keys.
    card.select_master_file()?;

    // Dump SOD
    let sod = card
        .read_file_cached(FileId::Sod)?
        .expect("SOD is manadatory");
    eprintln!("SOD LEN: {}", sod.len());

    // Parse as SecurityInfos
    match read_with_tag::<DocumentSecurityObject>(&sod, 0x77.try_into().unwrap()) {
        Err(e) => {
            eprintln!("SOD is not parsed: {:?}", e);
        }
        Ok(sod) => {
            // Ensure that the SOD is a SignedData and unwrap it.
            ensure!(sod.contents.oid == ID_SIGNED_DATA);
            let sod = sod.contents.contents;
            eprintln!("SOD is parsed: {:?}", sod);

            // Get Signature bytes
            let signature = sod.signer_infos.0.as_slice()[0].signature.as_bytes();

            // Hash of the signature bytes
            let hash = blake3::hash(signature);
            println!("DOCUMENT HASH = 0x{}", hex::encode(hash.as_bytes()));
        }
    }
    Ok(())
}

/// Helper function to read a DER-encoded value with an application specific tag.
pub fn read_with_tag<T>(data: &[u8], tag: Tag) -> Result<T>
where
    T: for<'a> DecodeValue<'a>,
{
    let any = AnyRef::from_der(data)?;
    ensure!(any.tag() == tag);
    let header = any.header()?;
    let mut reader = SliceReader::new(any.value())?;
    let value = T::decode_value(&mut reader, header)?;
    Ok(value)
}

pub const ID_SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DocumentSecurityObject {
    pub contents: IdentifiedData<SignedData>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct IdentifiedData<T: for<'a> Sequence<'a>> {
    // Should be `ID_SIGNED_DATA`
    pub oid: Oid,

    #[asn1(context_specific = "0")]
    pub contents: T,
}
