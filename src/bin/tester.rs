use {
    anyhow::Result,
    argh::FromArgs,
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    cms::{cert::CertificateChoices, signed_data},
    der::{Decode, Encode},
    glob::{glob, Pattern},
    hex_literal::hex,
    icao_9303_nfc::icao9303::asn1::{EfCardAccess, EfDg14, EfSod},
    serde::{Deserialize, Deserializer},
    std::{fmt::Debug, fs::File, io::BufReader, thread::panicking},
};

/// Test a parsing of exported eMRTD documents.
#[derive(FromArgs)]
struct Args {
    /// glob pattern for eMRTD documents as JSON/base64
    #[argh(positional)]
    documents: Pattern,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "UPPERCASE")]
struct Document {
    #[serde(deserialize_with = "deserialize_der")]
    com: der::Any,
    #[serde(default, deserialize_with = "deserialize_der", rename = "CardAccess")]
    card_access: Option<EfCardAccess>,
    #[serde(deserialize_with = "deserialize_der")]
    dg1: der::Any,
    #[serde(deserialize_with = "deserialize_der")]
    dg2: der::Any,
    #[serde(default, deserialize_with = "deserialize_der")]
    dg7: Option<der::Any>,
    #[serde(default, deserialize_with = "deserialize_der")]
    dg11: Option<der::Any>,
    #[serde(default, deserialize_with = "deserialize_der")]
    dg14: Option<EfDg14>,
    #[serde(deserialize_with = "deserialize_der")]
    sod: EfSod,
}

/// Serde helper to decode DER base64 encoded data.
fn deserialize_der<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: for<'a> Decode<'a> + Encode + Debug,
{
    // Decode Base64 DER
    let s: String = Deserialize::deserialize(deserializer)?;
    let b: Vec<u8> = BASE64.decode(&s).map_err(serde::de::Error::custom)?;
    let obj = T::from_der(&b).map_err(serde::de::Error::custom)?;

    // Check DER exact re-encoding
    let der = obj.to_der().map_err(serde::de::Error::custom)?;
    if b != der {
        eprintln!("DER encoding mismatch");
        eprintln!("  Expected: {}", hex::encode(&b));
        eprintln!("  Actual:   {}", hex::encode(&der));
        eprintln!("  Object:   {:?}", &obj);
        panic!();
    }

    Ok(obj)
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    for entry in glob(args.documents.as_str())? {
        let path = entry?;
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let document: Document = serde_json::from_reader(reader)?;
        println!(
            "Document with hash 0x{}",
            hex::encode(document.sod.document_hash())
        );
        let signed_data = document.sod.signed_data();
        let certs = signed_data.certificates.as_ref().unwrap();
        for cert in certs.0.iter() {
            match cert {
                CertificateChoices::Certificate(cert) => {
                    println!(" - Certificate:");
                    println!("   - Subject: {}", cert.tbs_certificate.subject);
                    println!("   - Issuer: {}", cert.tbs_certificate.issuer);
                    println!(
                        "   - Validity: {} to {}",
                        cert.tbs_certificate.validity.not_before,
                        cert.tbs_certificate.validity.not_after
                    );
                }
                CertificateChoices::Other(cert) => {
                    println!(" - Other certificate: {:?}", cert);
                    panic!("Unsupported certificate type");
                }
            }
        }

        // Get LDS Security Object and it's hash algorithm.
        let lso = document.sod.lds_security_object()?;
        let hasher = &lso.hash_algorithm;
        println!(" - SOD DG Hash: {}", hasher.name());

        // Check document hashes
        assert_eq!(lso.hash_for_dg(1).unwrap(), hasher.hash_der(&document.dg1));
        assert_eq!(lso.hash_for_dg(2).unwrap(), hasher.hash_der(&document.dg2));
        if let Some(dg7) = document.dg7.as_ref() {
            assert_eq!(lso.hash_for_dg(7).unwrap(), hasher.hash_der(dg7));
        }
        if let Some(dg11) = document.dg11.as_ref() {
            assert_eq!(lso.hash_for_dg(11).unwrap(), hasher.hash_der(dg11));
        }
        if let Some(dg14) = document.dg14.as_ref() {
            assert_eq!(lso.hash_for_dg(14).unwrap(), hasher.hash_der(dg14));
        }

        // Print CardAcces supported protocols
        if let Some(card_access) = document.card_access {
            for entry in card_access.iter() {
                println!(" - CardAccess: {}", entry.protocol_name(),);
            }
        }

        // Print DG14 supported protocols
        if let Some(dg14) = document.dg14 {
            for entry in dg14.0.iter() {
                println!(" - DG14: {}", entry.protocol_name());
            }
        }
    }
    Ok(())
}
