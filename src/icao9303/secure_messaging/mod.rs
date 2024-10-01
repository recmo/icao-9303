//! Secure Messaging

pub mod aes;
pub mod tdes;

use {
    super::pad,
    crate::iso7816::{parse_apdu, StatusWord},
    anyhow::{anyhow, ensure, Result},
};

pub const KDF_ENC: u32 = 1;
pub const KDF_MAC: u32 = 2;

pub trait SecureMessaging {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
    fn dec_response(&mut self, status: StatusWord, resp: &[u8]) -> Result<Vec<u8>>;
}

pub trait Cipher {
    fn block_size(&self) -> usize;

    fn enc(&self, data: &mut [u8]);
    fn dec(&self, data: &mut [u8]);
    fn mac(&self, data: &[u8]) -> [u8; 8];
}

/// Secure Messaging protocol that passes APDUs and responses as-is.
pub struct PlainText;

pub struct Encrypted<C: Cipher> {
    cipher: C,
    ssc: u64,
}

impl SecureMessaging for PlainText {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        Ok(apdu.to_vec())
    }

    fn dec_response(&mut self, _status: StatusWord, resp: &[u8]) -> Result<Vec<u8>> {
        Ok(resp.to_vec())
    }
}

impl<C: Cipher> Encrypted<C> {
    pub fn new(cipher: C, ssc: u64) -> Self {
        Self { cipher, ssc }
    }
}

impl<C: Cipher> SecureMessaging for Encrypted<C> {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        // Parse APDU
        let apdu = parse_apdu(apdu)?;
        let ins_even = apdu.ins() & 1 == 0;
        let extended_length = apdu.is_extended_length();

        // Write header
        let mut papdu = apdu.header.to_vec();
        papdu[0] |= 0x0C; // Set SM bit

        // Placeholder for data length
        papdu.extend_from_slice(if extended_length {
            &[0x00, 0x00, 0x00]
        } else {
            &[0x00]
        });

        // Write encrypted data
        if !apdu.data.is_empty() {
            let mut payload = apdu.data.to_vec();
            pad(&mut payload, self.cipher.block_size());
            self.cipher.enc(&mut payload);
            papdu.push(if ins_even { 0x87 } else { 0x85 });
            papdu.push((payload.len() + 1) as u8);
            papdu.push(0x01); // Tag for 80 00* padding
            papdu.extend_from_slice(&payload);
        }

        // Write Le
        if !apdu.le.is_empty() {
            papdu.push(0x97);
            papdu.push(apdu.le.len() as u8);
            papdu.extend_from_slice(apdu.le);
        }

        // Write MAC (mandatory)
        {
            // Increment send sequence counter
            self.ssc = self.ssc.wrapping_add(1);

            // Prepare MAC input
            let mut message = vec![0; self.cipher.block_size() - 8];
            message.extend_from_slice(&self.ssc.to_be_bytes());
            message.extend_from_slice(&papdu[..4]);
            pad(&mut message, self.cipher.block_size());
            if extended_length {
                message.extend_from_slice(&papdu[7..]);
            } else {
                message.extend_from_slice(&papdu[5..]);
            }
            pad(&mut message, self.cipher.block_size());

            // Compute MAC and append to papdu
            let mac = self.cipher.mac(&message);
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
        let mut n = vec![0; self.cipher.block_size() - 8];
        n.extend_from_slice(&self.ssc.to_be_bytes());
        n.extend_from_slice(resp);
        pad(&mut n, self.cipher.block_size());
        let mac2 = self.cipher.mac(&n);
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
        ensure!(resp.len() % self.cipher.block_size() == 0);
        self.cipher.dec(&mut resp);
        let length = resp
            .iter()
            .rposition(|&x| x == 0x80)
            .ok_or(anyhow!("Unpadding failed."))?;
        resp.truncate(length);

        Ok(resp)
    }
}
