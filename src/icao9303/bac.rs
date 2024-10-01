use {
    super::{
        secure_messaging::{
            tdes::{kdf, TDesSM},
            KDF_ENC, KDF_MAC,
        },
        Icao9303,
    },
    crate::crypto::{
        seed_from_mrz,
        tdes::{dec_3des, enc_3des, mac_3des},
    },
    anyhow::{anyhow, ensure, Result},
    rand::Rng,
    std::array,
};

impl Icao9303 {
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

    pub fn basic_access_control(&mut self, rng: &mut impl Rng, mrz: &str) -> Result<()> {
        // Compute local randomness
        let rnd_ifd: [u8; 8] = rng.gen();
        let k_ifd: [u8; 16] = rng.gen();

        // Compute encryption / authentication keys from MRZ
        let seed = seed_from_mrz(mrz);
        let kenc = kdf(&seed, KDF_ENC);
        let kmac = kdf(&seed, KDF_MAC);

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
