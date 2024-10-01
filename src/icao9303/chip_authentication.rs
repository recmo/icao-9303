use {
    super::Icao9303,
    anyhow::{ensure, Result},
    der::asn1::ObjectIdentifier as Oid,
};

impl Icao9303 {
    pub fn mset_at(&mut self, protocol: Oid, key_id: Option<u64>) -> Result<()> {
        // Send MSE Set AT to select the Chip Authentication protocol.
        let mut apdu = vec![0x00, 0x22, 0x41, 0xA4];
        apdu.push(0x00); // Placeholder length

        // Cryptographic mechanism: 0x80 <len> <OID>
        let protocol = protocol.as_bytes();
        apdu.push(0x80);
        apdu.push(protocol.len().try_into()?);
        apdu.extend_from_slice(protocol);

        // If the pivate key to be used has a reference, include it.
        if let Some(id) = key_id {
            apdu.push(0x84);
            apdu.push(0x01); // Assume id < 256
            apdu.push(id.try_into()?);
        }

        // Update length
        apdu[4] = (apdu.len() - 5).try_into()?;

        // Send MSE Set AT command to chip
        let (status, data) = self.send_apdu(&apdu)?;
        ensure!(status.is_success());
        ensure!(data.is_empty());
        Ok(())
    }

    pub fn general_authenticate(&mut self, public_key: &[u8]) -> Result<Vec<u8>> {
        // Send General Authenticate command to chip
        let mut apdu = vec![0x00, 0x86, 0x00, 0x00];
        apdu.push((public_key.len() + 4).try_into()?);
        apdu.push(0x7C);
        apdu.push((public_key.len() + 2).try_into()?);
        apdu.push(0x80);
        apdu.push(public_key.len().try_into()?);
        apdu.extend_from_slice(public_key);

        let (status, data) = self.send_apdu(&apdu)?;
        ensure!(status.is_success());
        Ok(data)
    }
}
