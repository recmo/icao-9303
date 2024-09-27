#![allow(dead_code)]

mod iso7816;
mod nfc;
mod tdes;

use {
    crate::{
        nfc::Nfc,
        tdes::{enc_3des, mac_3des},
    },
    anyhow::{anyhow, ensure, Result},
    der::{
        asn1::{AnyRef, ObjectIdentifier},
        Sequence, ValueOrd,
    },
    rand::Rng,
    sha1::{Digest, Sha1},
    std::env,
    tdes::set_parity_bits,
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
    requiredData: AnyRef<'a>,
    optionalData: Option<AnyRef<'a>>,
}

pub const MY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.127.0.7.2.2.4.2.4");

pub struct Icao9303 {
    nfc: Nfc,
}

impl Icao9303 {
    pub fn new(nfc: Nfc) -> Self {
        Self { nfc }
    }

    pub fn select_master_file(&mut self) -> Result<()> {
        // Select by file identifier
        // See ISO/IEC 7816-4 section 11.2.2
        let (status, data) = self
            .nfc
            .send_apdu(&[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])?;
        if !status.is_success() && status.data_remaining().is_none() {
            return Err(anyhow!("Failed to select master file: {}", status));
        }
        ensure!(data.is_empty());
        Ok(())
    }

    pub fn select_dedicated_file(&mut self, application_id: &[u8]) -> Result<()> {
        ensure!(application_id.len() <= 16);
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x0C, application_id.len() as u8];
        apdu.extend_from_slice(application_id);
        let (status, data) = self.nfc.send_apdu(&apdu)?;
        if !status.is_success() && status.data_remaining().is_none() {
            return Err(anyhow!(
                "Failed to select dedicated file {}: {}",
                hex::encode_upper(application_id),
                status
            ));
        }
        ensure!(data.is_empty());
        Ok(())
    }

    pub fn select_elementary_file(&mut self, file: u16) -> Result<()> {
        // Select by elementary file by file identifier.
        // Not the application DF has to be previously selected.
        // See ISO/IEC 7816-4 section 11.2.2
        // See ICAO 9303-10 section 3.6.2
        let file_bytes = file.to_be_bytes();
        let (status, data) =
            self.nfc
                .send_apdu(&[0x00, 0xA4, 0x02, 0x0C, 0x02, file_bytes[0], file_bytes[1]])?;
        if !status.is_success() && status.data_remaining().is_none() {
            return Err(anyhow!(
                "Failed to select dedicated file {:04X}: {}",
                file,
                status
            ));
        }
        ensure!(data.is_empty());
        Ok(())
    }

    /// Read binary data from an elementary file using a Short EF identifier.
    ///
    /// This is the recommended way to read data from an elementary file.
    ///
    /// See ICAO 9303-10 section 3.6.3.2 and ISO 7816-4 section 11.3.3.
    // TODO: Check for extended length support before using.
    // See ICAO 9303-10 section 3.6.4.2.
    pub fn read_binary_short_ef(&mut self, file: u8) -> Result<Vec<u8>> {
        ensure!(file <= 0x1F);
        // Note b8 of p2 must be set to 1 to indicate that a short file id is used.
        // Setting P2 to 0 means 'offset zero'.
        // Setting Le to 0x000000 means 'read all' with extended length.
        let apdu = [0x00, 0xB0, 0x80 | file, 0x00, 0x00, 0x00, 0x00];
        let (status, data) = self.nfc.send_apdu(&apdu)?;
        if !status.is_success() {
            // TODO: Special case 'not found'.
            return Err(anyhow!("Failed to read file: {}", status));
        }
        ensure!(status.data_remaining() == None);
        Ok(data)
    }

    /// Get random nonce for authentication.
    ///
    /// See ICAO 9303-11 section 4.3.4.1.
    pub fn get_challenge(&mut self) -> Result<Vec<u8>> {
        let (status, data) = self.nfc.send_apdu(&[0x00, 0x84, 0x00, 0x00, 0x08])?;
        if !status.is_success() {
            return Err(anyhow!("Failed to get challenge: {}", status));
        }
        ensure!(status.data_remaining() == None);
        ensure!(data.len() == 8);
        Ok(data)
    }

    pub fn external_authenticate(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        assert_eq!(data.len(), 0x28);
        let mut apdu = vec![0x00, 0x82, 0x00, 0x00, 0x28];
        apdu.extend_from_slice(data);
        apdu.push(0x00);
        let (status, data) = self.nfc.send_apdu(&apdu)?;
        if !status.is_success() {
            return Err(anyhow!("Failed to authenticate: {}", status));
        }
        Ok(data)
    }

    pub fn read_elementary_file(&mut self, file: u16) -> Result<Vec<u8>> {
        let file = file.to_be_bytes();

        // Select by file identifier
        // See ISO/IEC 7816-4 section 11.2.2
        // See ICAO 9303-10 section 3.6.2
        let (status, data) = self
            .nfc
            .send_apdu(&[0x00, 0xA4, 0x02, 0x0C, 0x02, file[0], file[1]])?;
        if !status.is_success() && status.data_remaining().is_none() {
            return Err(anyhow!("Failed to select file: {}", status));
        }
        ensure!(data.is_empty());

        // Read file
        // Requesting 0xFF bytes is a hack to get the full file content.
        // TODO: Implement proper handling.
        let (status, data) = self
            .nfc
            .send_apdu(&[0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0xFF])?;
        if !status.is_success() {
            return Err(anyhow!("Failed to read file: {}", status));
        }
        ensure!(status.data_remaining() == None);

        Ok(data)
    }
}

fn main() -> Result<()> {
    // Find and open the Proxmark3 device
    let mut nfc = Nfc::new_proxmark3()?;

    // TODO: Implement full ICAO-9303-4.2 Chip Access Procedure.

    // Connect to ISO 14443-A card as reader, keeping the field on.
    nfc.connect()?;
    let mut card = Icao9303::new(nfc);

    // See ICAO 9303-10 figure 3 for file structure.

    // Read CardAccess file using short EF.
    // Presence means PACE is supported.
    // card.select_master_file()?;
    // let data = card.read_binary_short_ef(0x1C)?;
    // println!("CardAccess: {}", hex::encode(data));

    // Initiate Basic Authentication.

    // Read MRZ from environment variable.
    let mrz_str = env::var("MRZ")?;
    println!("Using MRZ: {}", mrz_str);

    // Compute encryption / authentication keys from MRZ
    let (kenc, kmac) = derive_keys(&seed_from_mrz(&mrz_str));
    println!("kenc: {}", hex::encode(kenc));
    println!("kmac: {}", hex::encode(kmac));

    // GET CHALLENGE
    let rnd_ic = card.get_challenge()?;
    println!("rnd.ic: {}", hex::encode(&rnd_ic));

    let mut rng = rand::thread_rng();
    let rnd_ifd: [u8; 8] = rng.gen();
    let k_ifd: [u8; 16] = rng.gen();
    println!("rnd.ifd: {}", hex::encode(rnd_ifd));
    println!("k.ifd: {}", hex::encode(k_ifd));

    let mut msg = vec![];
    msg.extend_from_slice(&rnd_ifd);
    msg.extend_from_slice(&rnd_ic);
    msg.extend_from_slice(&k_ifd);

    enc_3des(&kenc, &mut msg);
    msg.extend(mac_3des(&kmac, &msg));

    // EXTERNAL AUTHENTICATE
    card.external_authenticate(&msg)?;

    Ok(())
}

pub fn seed_from_mrz(mrz: &str) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(mrz.as_bytes());
    let hash = hasher.finalize();
    hash[0..16].try_into().unwrap()
}

pub fn derive_keys(seed: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    (derive_key(seed, 1), derive_key(seed, 2))
}

pub fn derive_key(seed: &[u8; 16], counter: u32) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(seed);
    hasher.update(counter.to_be_bytes());
    let hash = hasher.finalize();
    let mut key: [u8; 16] = hash[0..16].try_into().unwrap();
    set_parity_bits(&mut key);
    key
}

#[test]
/// Example from ICAO 9303-11 section D.2
fn test_bac_example() {
    let mrz = "L898902C<369080619406236";
    let seed = seed_from_mrz(mrz);
    assert_eq!(seed, hex!("239AB9CB282DAF66231DC5A4DF6BFBAE"));

    let (kenc, kmac) = derive_keys(&seed);
    assert_eq!(kenc, hex!("AB94FDECF2674FDFB9B391F85D7F76F2"));
    assert_eq!(kmac, hex!("7962D9ECE03D1ACD4C76089DCE131543"));
}
