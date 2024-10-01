mod status_word;

pub use self::status_word::StatusWord;
use anyhow::{bail, ensure, Result};

#[derive(Debug)]
pub struct ApduRef<'a> {
    pub header: &'a [u8],
    pub lc: &'a [u8],
    pub data: &'a [u8],
    pub le: &'a [u8],
}

impl ApduRef<'_> {
    pub fn cla(&self) -> u8 {
        self.header[0]
    }

    pub fn ins(&self) -> u8 {
        self.header[1]
    }

    pub fn p1(&self) -> u8 {
        self.header[2]
    }

    pub fn p2(&self) -> u8 {
        self.header[3]
    }

    pub fn is_extended_length(&self) -> bool {
        self.lc.len() > 1 || self.le.len() > 1
    }
}

/// Parse APDU into header, Lc, data, and Le.
/// See ISO 7816-4 section 5.2
pub fn parse_apdu(apdu: &[u8]) -> Result<ApduRef> {
    ensure!(apdu.len() <= 128); // TODO: What is the real maximum?
    let empty = &apdu[0..0];
    Ok(match (apdu.len(), apdu.get(4)) {
        (0..4, _) => bail!("APDU to short"),
        // Short without data and no Le
        (4, None) => ApduRef {
            header: &apdu[..4],
            lc: empty,
            data: empty,
            le: empty,
        },
        // Short without data and with Le
        (5, _) => ApduRef {
            header: &apdu[..4],
            lc: empty,
            data: empty,
            le: &apdu[4..5],
        },
        (6, Some(&0x00)) => bail!("Invalid Lc"),
        // Extended length, no data
        (7, Some(&0x00)) => ApduRef {
            header: &apdu[..4],
            lc: empty,
            data: empty,
            le: &apdu[4..],
        },
        // Extended length with data and maybe Le
        (_, Some(&0x00)) => {
            let lc = u16::from_be_bytes([apdu[4], apdu[5]]) as usize;
            ensure!(lc > 0, "Invalid Lc");
            if apdu.len() - 7 == lc {
                // Extended length with data and no Le
                ApduRef {
                    header: &apdu[..4],
                    lc: &apdu[4..7],
                    data: &apdu[7..],
                    le: empty,
                }
            } else if apdu.len() - 9 == lc {
                // Extended length with data and Le
                ApduRef {
                    header: &apdu[..4],
                    lc: &apdu[4..7],
                    data: &apdu[7..7 + lc],
                    le: &apdu[7 + lc..],
                }
            } else {
                bail!("Invalid extended length APDU encoding")
            }
        }
        // Short with data and no Le
        (_, Some(&lc)) if apdu.len() - 5 == lc as usize => ApduRef {
            header: &apdu[..4],
            lc: &apdu[4..5],
            data: &apdu[5..],
            le: empty,
        },
        // Short with data and Le
        (_, Some(&lc)) if apdu.len() - 6 == lc as usize => ApduRef {
            header: &apdu[..4],
            lc: &apdu[4..5],
            data: &apdu[5..apdu.len() - 1],
            le: &apdu[apdu.len() - 1..],
        },
        _ => bail!("Invalid APDU encoding"),
    })
}
