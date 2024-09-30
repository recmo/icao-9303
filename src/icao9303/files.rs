use {
    super::Icao9303,
    anyhow::{anyhow, ensure, Result},
    std::io::Write,
};

impl Icao9303 {
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
        // Setting Le to 0x00 means read up to 256 / 65536.
        let (status, data) = if self.extended_length {
            // Setting Le to 0x000000 means 'read all' with extended length.
            let apdu = [0x00, 0xB0, 0x80 | file, 0x00, 0x00, 0x00, 0x00];
            self.send_apdu(&apdu)?
        } else {
            // Setting Le to 0x00 means 'read all'.
            let apdu = [0x00, 0xB0, 0x80 | file, 0x00, 0xFF];
            self.send_apdu(&apdu)?
        };
        if !status.is_success() {
            // TODO: Special case 'not found'.
            return Err(anyhow!("Failed to read file: {}", status));
        }
        ensure!(status.data_remaining() == None);
        Ok(data)
    }

    pub fn read_file(&mut self, file: u8) -> Result<Vec<u8>> {
        const MIN_SIZE: usize = 200; // TODO: Check this value.

        // Read first bytes and make file current.
        print!(".");
        std::io::stdout().flush().unwrap();
        let mut result = self.read_binary_short_ef(file)?;

        // For short files we are done.
        if result.len() < MIN_SIZE {
            println!();
            return Ok(result);
        }

        // Read remaining bytes.
        loop {
            // TODO: Use 0xB1 to read larger files.
            ensure!(result.len() < 65536);
            let offset = (result.len() as u16).to_be_bytes();
            print!(".");
            std::io::stdout().flush().unwrap();
            let (status, data) = self.send_apdu(&[0x00, 0xB0, offset[0], offset[1], 0xFF])?;
            if !status.is_success() {
                return Err(anyhow!("Failed to read file: {}", status));
            }
            result.extend(&data);
            if data.len() < MIN_SIZE {
                break;
            }
        }

        println!("");
        Ok(result)
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
}
