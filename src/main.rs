#![allow(dead_code)]

mod iso7816;
mod nfc;
mod tdes;

use {
    crate::{
        nfc::Nfc,
        tdes::{dec_3des, enc_3des, mac_3des},
    },
    anyhow::{anyhow, ensure, Result},
    der::{
        asn1::{AnyRef, ObjectIdentifier},
        Header, Sequence, ValueOrd,
    },
    hex_literal::hex,
    iso7816::StatusWord,
    rand::Rng,
    sha1::{Digest, Sha1},
    std::{array, env},
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
    secure_messaging: Box<dyn SecureMessaging>,
}

impl Icao9303 {
    pub fn new(nfc: Nfc) -> Self {
        Self {
            nfc,
            secure_messaging: Box::new(PlainText),
        }
    }

    pub fn select_master_file(&mut self) -> Result<()> {
        // Select by file identifier
        // See ISO/IEC 7816-4 section 11.2.2
        let (status, data) = self.send_apdu(&[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])?;
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
        let (status, data) = self.send_apdu(&apdu)?;
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
            self.send_apdu(&[0x00, 0xA4, 0x02, 0x0C, 0x02, file_bytes[0], file_bytes[1]])?;
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
        let (status, data) = self.send_apdu(&apdu)?;
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
        let (status, data) = self.send_apdu(&[0x00, 0x84, 0x00, 0x00, 0x08])?;
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
        let (status, data) = self.send_apdu(&apdu)?;
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
        let (status, data) = self.send_apdu(&[0x00, 0xA4, 0x02, 0x0C, 0x02, file[0], file[1]])?;
        if !status.is_success() && status.data_remaining().is_none() {
            return Err(anyhow!("Failed to select file: {}", status));
        }
        ensure!(data.is_empty());

        // Read file
        // Requesting 0xFF bytes is a hack to get the full file content.
        // TODO: Implement proper handling.
        let (status, data) = self.send_apdu(&[0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0xFF])?;
        if !status.is_success() {
            return Err(anyhow!("Failed to read file: {}", status));
        }
        ensure!(status.data_remaining() == None);

        Ok(data)
    }

    pub fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        let protected_apdu = self.secure_messaging.enc_apdu(apdu)?;
        let (status, data) = self.nfc.send_apdu(&protected_apdu)?;

        // TODO: On SM error card will revert to plain APDU.
        let data = self.secure_messaging.dec_response(status, &data)?;
        Ok((status, data))
    }

    pub fn basic_access_control(&mut self, mrz: &str) -> Result<()> {
        let mut rng = rand::thread_rng();

        // Compute local randomness
        let rnd_ifd: [u8; 8] = rng.gen();
        let k_ifd: [u8; 16] = rng.gen();

        // Compute encryption / authentication keys from MRZ
        let seed = seed_from_mrz(mrz);
        let (kenc, kmac) = derive_keys(&seed);

        // GET CHALLENGE
        let rnd_ic = self.get_challenge()?;

        // Construct authentication data
        let mut msg = vec![];
        msg.extend_from_slice(&rnd_ifd);
        msg.extend_from_slice(&rnd_ic);
        msg.extend_from_slice(&k_ifd);
        enc_3des(&kenc, &mut msg);
        msg.extend(mac_3des(&kmac, &msg));

        // EXTERNAL AUTHENTICATE
        let mut resp_data = self.external_authenticate(&msg)?;
        ensure!(resp_data.len() == 40);

        // Check MAC and decrypt response
        let mac = mac_3des(&kmac, &resp_data[..32]);
        ensure!(&resp_data[32..] == &mac[..]);
        dec_3des(&kenc, &mut resp_data[..32]);
        let resp_data = &resp_data[..32];

        // Check nonce consistency
        ensure!(&resp_data[0..8] == &rnd_ic[..]);
        ensure!(&resp_data[8..16] == &rnd_ifd[..]);
        let k_ic: [u8; 16] = resp_data[16..].try_into().unwrap();

        // Construct seed and ssc for session keys
        let seed: [u8; 16] = array::from_fn(|i| k_ifd[i] ^ k_ic[i]);

        // Construct initial send sequence counter
        // See ICAO 9303-10 section 9.8.6.3
        let mut ssc_bytes = vec![];
        ssc_bytes.extend_from_slice(&rnd_ic[4..]);
        ssc_bytes.extend_from_slice(&rnd_ifd[4..]);
        let ssc: u64 = u64::from_be_bytes(ssc_bytes[..8].try_into().unwrap());

        // Add TDES session keys to secure messaging
        let tdes = TDesSM::from_seed(seed, ssc);
        self.secure_messaging = Box::new(tdes);

        Ok(())
    }
}

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

    // See ICAO 9303-10 figure 3 for file structure.

    // Read CardAccess file using short EF.
    // Presence means PACE is supported.
    println!("=== Select master file.");
    card.select_master_file()?;
    println!("=== Read CardAccess.");
    let data = card.read_binary_short_ef(0x1C)?;
    println!("CardAccess: {}", hex::encode(data));

    println!("=== Basic Access Control.");
    let mrz = env::var("MRZ")?;
    card.basic_access_control(&mrz)?;

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
        println!("==> EF.COM: {}", hex::encode(data));
    }
    if let Ok(data) = card.read_binary_short_ef(0x01) {
        println!("==> EF.DG1: {}", hex::encode(data));
    }
    // if let Ok(data) = card.read_binary_short_ef(0x02) {
    //     println!("==> EF.DG2: {}", hex::encode(data));
    // }
    if let Ok(data) = card.read_binary_short_ef(0x1D) {
        println!("==> EF.SOD: {}", hex::encode(data));
    }

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

pub trait SecureMessaging {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
    fn dec_response(&mut self, status: StatusWord, resp: &[u8]) -> Result<Vec<u8>>;
}

pub struct PlainText;

impl SecureMessaging for PlainText {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        Ok(apdu.to_vec())
    }

    fn dec_response(&mut self, _status: StatusWord, resp: &[u8]) -> Result<Vec<u8>> {
        Ok(resp.to_vec())
    }
}

pub struct TDesSM {
    kenc: [u8; 16],
    kmac: [u8; 16],
    ssc: u64,
}

impl TDesSM {
    pub fn from_seed(seed: [u8; 16], ssc: u64) -> Self {
        let (kenc, kmac) = derive_keys(&seed);
        Self { kenc, kmac, ssc }
    }
}

impl SecureMessaging for TDesSM {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        ensure!(apdu.len() >= 4);
        ensure!(apdu.len() <= 128); // TODO: What is the real maximum?
        println!("apdu: {}", hex::encode(apdu));

        // Parse APDU
        // See ISO 7816-4 section 5.2
        let (header, apdu) = apdu.split_at(4);
        let (lc, data, le) = if apdu.is_empty() {
            // No data, no Le
            (&apdu[0..0], &apdu[0..0], &apdu[0..0])
        } else if apdu[0] != 0x00 {
            // Short lengths
            if apdu.len() == 1 {
                // No data, only Le
                (&apdu[0..0], &apdu[0..0], &apdu[0..1])
            } else {
                let lc = apdu[0] as usize;
                (&apdu[0..1], &apdu[1..lc + 1], &apdu[lc + 1..])
            }
        } else if apdu.len() == 3 {
            // Extended lengths, Le only
            (&apdu[0..0], &apdu[0..0], &apdu[1..3])
        } else {
            ensure!(apdu.len() > 3);
            // Extended lengths with data
            let lc = &apdu[1..2];
            let nc = u16::from_be_bytes(lc.try_into().unwrap()) as usize;
            ensure!(apdu.len() >= 3 + nc);
            (&apdu[1..3], &apdu[3..nc + 3], &apdu[nc + 3..])
        };
        let ins_even = header[1] & 1 == 0;
        let extended_length = lc.len() > 1 || le.len() > 1;

        // Write header
        let mut papdu = header.to_vec();
        papdu[0] |= 0x0C; // Set SM bit

        // Placeholder for data length
        papdu.extend_from_slice(if extended_length {
            &[0x00, 0x00, 0x00]
        } else {
            &[0x00]
        });

        // Write encrypted data
        if !data.is_empty() {
            let mut payload = data.to_vec();
            pad(&mut payload);
            enc_3des(&self.kenc, &mut payload);
            papdu.push(if ins_even { 0x87 } else { 0x85 });
            papdu.push((payload.len() + 1) as u8);
            papdu.push(0x01); // Tag for 80 00* padding
            papdu.extend_from_slice(&payload);
        }

        // Write Le
        if !le.is_empty() {
            papdu.push(0x97);
            papdu.push(le.len() as u8);
            papdu.extend_from_slice(le);
        }

        // Write MAC (mandatory)
        {
            // Increment send sequence counter
            self.ssc = self.ssc.wrapping_add(1);

            // Prepare MAC input
            let mut message = Vec::new();
            message.extend_from_slice(&self.ssc.to_be_bytes());
            message.extend_from_slice(&papdu[..4]);
            pad(&mut message);
            if extended_length {
                message.extend_from_slice(&papdu[7..]);
            } else {
                message.extend_from_slice(&papdu[5..]);
            }

            // Compute MAC and append to papdu
            let mac = mac_3des(&self.kmac, &message);
            papdu.push(0x8E);
            papdu.push(mac.len() as u8);
            papdu.extend_from_slice(&mac);
        }

        // Patch data length
        if extended_length {
            let len = papdu.len() - 7;
            papdu[5] = (len >> 8) as u8;
            papdu[6] = (len & 0xFF) as u8;
        } else {
            papdu[4] = (papdu.len() - 5) as u8;
        }

        // Write Le
        if extended_length {
            papdu.extend_from_slice(&[0x00, 0x00]);
        } else {
            papdu.extend_from_slice(&[0x00]);
        };

        Ok(papdu)
    }

    fn dec_response(&mut self, status: StatusWord, resp: &[u8]) -> Result<Vec<u8>> {
        ensure!(resp.len() >= 14);

        // Split off DO'8E object containing MAC
        let (resp, mac) = resp.split_at(resp.len() - 10);
        ensure!(mac[0] == 0x8E);
        ensure!(mac[1] == 0x08);
        let mac = &mac[2..];

        // Compute and verify MAC
        self.ssc = self.ssc.wrapping_add(1);
        let mut n = self.ssc.to_be_bytes().to_vec();
        n.extend_from_slice(resp);
        let mac2 = mac_3des(&self.kmac, &n);
        println!("mac: {}", hex::encode(mac2));
        ensure!(mac == mac2);

        // Split off DO'99 object and check (redundant) status word.
        // TODO: DO'99 is optional, so we should check if it's present.
        // TODO: DO'99 is allowed to be empty.
        let (resp, do99) = resp.split_at(resp.len() - 4);
        ensure!(do99[0] == 0x99);
        ensure!(do99[1] == 0x02);
        ensure!(do99[2] == status.sw1());
        ensure!(do99[3] == status.sw2());

        // If no data remaining there was no response data
        if resp.is_empty() {
            return Ok(Vec::new());
        }

        // Decrypt DO'87 response data object
        // TODO: Allow for trailing data.
        ensure!(resp.len() >= 11);
        ensure!(resp[0] == 0x85 || resp[0] == 0x87);
        ensure!(resp[1] == (resp.len() - 2) as u8);
        ensure!(resp[2] == 0x01);
        let mut resp = resp[3..].to_vec();
        dec_3des(&self.kenc, &mut resp);
        let length = resp
            .iter()
            .rposition(|&x| x == 0x80)
            .ok_or(anyhow!("Unpadding failed."))?;
        resp.truncate(length);

        Ok(resp)
    }
}

pub fn pad(bytes: &mut Vec<u8>) {
    bytes.push(0x80);
    bytes.resize(bytes.len().next_multiple_of(8), 0x00);
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    /// Example from ICAO 9303-11 section D.2
    #[test]
    fn test_bac_example() {
        let mrz = "L898902C<369080619406236";
        let seed = seed_from_mrz(mrz);
        assert_eq!(seed, hex!("239AB9CB282DAF66231DC5A4DF6BFBAE"));

        let (kenc, kmac) = derive_keys(&seed);
        assert_eq!(kenc, hex!("AB94FDECF2674FDFB9B391F85D7F76F2"));
        assert_eq!(kmac, hex!("7962D9ECE03D1ACD4C76089DCE131543"));
    }

    // Example from ICAO 9303-11 section D.2
    #[test]
    fn test_derive_keys() {
        let k_seed = hex!("0036D272F5C350ACAC50C3F572D23600");
        let (kenc, kmac) = derive_keys(&k_seed);
        assert_eq!(kenc, hex!("979EC13B1CBFE9DCD01AB0FED307EAE5"));
        assert_eq!(kmac, hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"));
    }

    // Example from ICAO 9303-11 section D.4
    #[test]
    fn test_tdes_sm() {
        let seed = hex!("0036D272F5C350ACAC50C3F572D23600");
        let ssc = 0x887022120C06C226;
        let mut tdes = TDesSM::from_seed(seed, ssc);

        // Select EF.COM
        let apdu = hex!("00 A4 02 0C 02 01 1E");
        let papdu = tdes.enc_apdu(&apdu).unwrap();
        assert_eq!(
            papdu,
            hex!("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800")
        );
        let rapdu = hex!("990290008E08FA855A5D4C50A8ED");
        let dec = tdes.dec_response(0x9000.into(), &rapdu).unwrap();
        assert_eq!(dec, hex!(""));

        // Read Binary of first four bytes
        let apdu = hex!("00 B0 00 00 04");
        let papdu = tdes.enc_apdu(&apdu).unwrap();
        assert_eq!(papdu, hex!("0CB000000D9701048E08ED6705417E96BA5500"));
        let rapdu = hex!("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED");
        let data = tdes.dec_response(0x9000.into(), &rapdu).unwrap();
        assert_eq!(data, hex!("60145F01"));

        // Read Binary of remaining 18 bytes from offset 4
        let apdu = hex!("00 B0 00 04 12");
        let papdu = tdes.enc_apdu(&apdu).unwrap();
        assert_eq!(papdu, hex!("0CB000040D9701128E082EA28A70F3C7B53500"));
        let rapdu = hex!(
            "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D74"
        );
        let data = tdes.dec_response(0x9000.into(), &rapdu).unwrap();
        assert_eq!(data, hex!("04303130365F36063034303030305C026175"));
    }
}
