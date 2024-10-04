mod file_id;

pub use self::file_id::{DedicatedId, FileId};
use {
    super::{
        asn1::{read_with_tag, DocumentSecurityObject},
        Error, Icao9303, Result,
    },
    crate::{ensure_err, icao9303::asn1::ID_SIGNED_DATA, iso7816::StatusWord},
    cms::signed_data::SignedData,
    std::collections::HashMap,
};

pub type FileCache = HashMap<FileId, Option<Vec<u8>>>;

impl Icao9303 {
    pub fn ef_sod(&mut self) -> Result<SignedData> {
        let ef_sod = self
            .read_file_cached(FileId::Sod)?
            .ok_or(Error::ResponseTooLong)?;

        let parsed =
            read_with_tag::<DocumentSecurityObject>(ef_sod.as_slice(), 0x77.try_into().unwrap())
                .expect("Error parsing DER");
        assert!(parsed.contents.oid == ID_SIGNED_DATA);
        Ok(parsed.contents.contents)
    }

    /// Retrieves a file with caching.
    ///
    /// Returns Ok(None) if the file is not found.
    pub fn read_file_cached(&mut self, file: FileId) -> Result<Option<Vec<u8>>> {
        const MIN_SIZE: usize = 200; // TODO: Check this value.

        // Try cache first.
        if let Some(entry) = self.file_cache.get(&file) {
            return Ok(entry.clone());
        }

        // Select parent file if necessary.
        if self.parent != file.parent() {
            if let Some(application_id) = file.parent().aid() {
                self.select_dedicated_file(application_id)?;
            } else {
                self.select_master_file()?;
            }
        }

        // Read file by short EF.
        let mut result: Option<Vec<u8>> = match self.read_binary_short_ef(file.short_id()) {
            Ok(data) => Some(data),
            Err(Error::ErrorResponse(StatusWord::FILE_NOT_FOUND)) => None,
            Err(e) => return Err(e),
        };
        if let Some(result) = result.as_mut() {
            if result.len() >= MIN_SIZE {
                // Read remaining bytes.
                loop {
                    // TODO: Use 0xB1 to read larger files.
                    if result.len() > 65536 {
                        return Err(Error::ResponseTooLong);
                    }
                    let offset = (result.len() as u16).to_be_bytes();
                    let (status, data) =
                        self.send_apdu(&[0x00, 0xB0, offset[0], offset[1], 0xFF])?;
                    ensure_err!(status.is_success(), status.into());
                    result.extend(&data);
                    if data.len() < MIN_SIZE {
                        break;
                    }
                }
            }
        }

        // Insert in cache
        self.file_cache.insert(file, result.clone());
        Ok(result)
    }

    pub fn select_master_file(&mut self) -> Result<()> {
        // Select by file identifier
        // See ISO/IEC 7816-4 section 11.2.2
        let (status, data) = self.send_apdu(&[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])?;
        ensure_err!(status.is_success(), status.into());
        self.parent = DedicatedId::MasterFile;
        ensure_err!(data.is_empty(), Error::ResponseDataUnexpected);
        Ok(())
    }

    pub fn select_dedicated_file(&mut self, application_id: &[u8]) -> Result<()> {
        if application_id.len() > 16 {
            return Err(Error::InvalidApplicationId);
        }
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x0C, application_id.len() as u8];
        apdu.extend_from_slice(application_id);
        let (status, data) = self.send_apdu(&apdu)?;
        ensure_err!(status.is_success(), status.into());
        self.parent = DedicatedId::from_aid(application_id);
        ensure_err!(data.is_empty(), Error::ResponseDataUnexpected);
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
        ensure_err!(status.is_success(), status.into());
        ensure_err!(data.is_empty(), Error::ResponseDataUnexpected);
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
        if file > 0x1F {
            return Err(Error::InvalidShortFileId);
        }
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
        ensure_err!(status.is_success(), status.into());
        Ok(data)
    }
}
