//! 3DES Secure Messasing

use {
    super::{SecureMessaging, KDF_ENC, KDF_MAC},
    crate::{
        crypto::{
            pad,
            tdes::{dec_3des, enc_3des, mac_3des, set_parity_bits},
        },
        iso7816::StatusWord,
    },
    anyhow::{anyhow, ensure, Result},
    sha1::{Digest, Sha1},
};

pub struct TDesSM {
    kenc: [u8; 16],
    kmac: [u8; 16],
    ssc: u64,
}

pub fn kdf(seed: &[u8; 16], counter: u32) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(seed);
    hasher.update(counter.to_be_bytes());
    let hash = hasher.finalize();
    let mut key: [u8; 16] = hash[0..16].try_into().unwrap();
    set_parity_bits(&mut key);
    key
}

impl TDesSM {
    pub fn from_seed(seed: [u8; 16], ssc: u64) -> Self {
        Self {
            kenc: kdf(&seed, KDF_ENC),
            kmac: kdf(&seed, KDF_MAC),
            ssc,
        }
    }
}

impl SecureMessaging for TDesSM {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        ensure!(apdu.len() >= 4);
        ensure!(apdu.len() <= 128); // TODO: What is the real maximum?

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
        // Parse BER-TLV length
        let (tl_len, length) = match resp[1] {
            0x00..=0x7F => (2, resp[1] as usize),
            0x81 => (3, resp[2] as usize),
            0x82 => (4, u16::from_be_bytes([resp[2], resp[3]]) as usize),
            0x83 => (
                5,
                u32::from_be_bytes([0, resp[2], resp[3], resp[4]]) as usize,
            ),
            0x84 => (
                6,
                u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize,
            ),
            _ => {
                return Err(anyhow!("Invalid BER-TLV length."));
            }
        };
        let resp = &resp[tl_len..];
        ensure!(resp.len() == length);
        ensure!(resp[0] == 0x01);
        let mut resp = resp[1..].to_vec();
        dec_3des(&self.kenc, &mut resp);
        let length = resp
            .iter()
            .rposition(|&x| x == 0x80)
            .ok_or(anyhow!("Unpadding failed."))?;
        resp.truncate(length);

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::crypto::seed_from_mrz, hex_literal::hex};

    /// Example from ICAO 9303-11 section D.2
    #[test]
    fn test_bac_example() {
        let mrz = "L898902C<369080619406236";
        let seed = seed_from_mrz(mrz);
        assert_eq!(seed, hex!("239AB9CB282DAF66231DC5A4DF6BFBAE"));

        let (kenc, kmac) = (kdf(&seed, KDF_ENC), kdf(&seed, KDF_MAC));
        assert_eq!(kenc, hex!("AB94FDECF2674FDFB9B391F85D7F76F2"));
        assert_eq!(kmac, hex!("7962D9ECE03D1ACD4C76089DCE131543"));
    }

    // Example from ICAO 9303-11 section D.2
    #[test]
    fn test_derive_keys() {
        let k_seed = hex!("0036D272F5C350ACAC50C3F572D23600");
        let (kenc, kmac) = (kdf(&k_seed, KDF_ENC), kdf(&k_seed, KDF_MAC));
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
