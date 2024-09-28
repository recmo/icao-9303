#![cfg(feature = "proxmark3")]
//! Proxmark3 Driver with partial ISO 14443-A support.
//!
//! Implements the USB protocol to communicate with the Proxmark3 device.

mod usb; // TODO: BLE

use {
    self::usb::UsbConnection,
    super::NfcReader,
    crate::iso7816::StatusWord,
    anyhow::{ensure, Result},
    bytes::{Buf, BufMut, BytesMut},
    crc::{Crc, CRC_16_ISO_IEC_14443_3_A},
    std::array,
};

#[repr(u16)]
pub enum Command {
    DebugPrintString = 0x0100, // Used for error responses.

    NotAck = 0x00FE,
    Ack = 0x00FF,

    Ping = 0x0109,
    Capabilities = 0x0112,
    Version = 0x0107,
    QuitSession = 0x0113,

    Hf14aReader = 0x0385,
}

#[repr(i16)]
pub enum Status {
    Success = 0,
    UndefinedError = -1,
    InvalidArgument = -2,
}

pub struct Proxmark3 {
    connection: Box<dyn Connection>,
    crc: bool,
    trace: bool,
}

/// Connection to a Proxmark3 UART interface.
trait Connection {
    fn read(&mut self, buffer: &mut [u8]) -> Result<()>;
    fn write(&mut self, data: &[u8]) -> Result<()>;
    fn close(self) -> Result<()>;
}

impl Proxmark3 {
    pub fn new() -> Result<Self> {
        let connection = UsbConnection::new()?;
        let mut proxmark3 = Proxmark3::from_connection(Box::new(connection));
        proxmark3.test_connection()?;
        Ok(proxmark3)
    }

    pub fn close(mut self) -> Result<()> {
        self.send_command_ng(Command::QuitSession, &[])?;
        // self.connection.close()?;
        Ok(())
    }

    fn from_connection(connection: Box<dyn Connection>) -> Self {
        Proxmark3 {
            connection,
            crc: true,
            trace: true,
        }
    }

    fn test_connection(&mut self) -> Result<()> {
        // TODO: Flush device read buffer.

        // Ping the Proxmark3
        // https://github.com/RfidResearchGroup/proxmark3/blob/55ef252a5d0d590026a4959a4c1b7a6028d1ad13/client/src/comms.c#L827
        let data: [u8; 32] = array::from_fn(|i| i as u8);
        self.send_command_ng(Command::Ping, &data)?;
        let (status, cmd, response) = self.receive_response()?;
        ensure!(status == Status::Success as i16);
        ensure!(cmd == Command::Ping as u16);
        ensure!(response == data);

        // Check capabilities
        self.send_command_ng(Command::Capabilities, &[])?;
        let (status, cmd, response) = self.receive_response()?;
        ensure!(status == Status::Success as i16);
        ensure!(cmd == Command::Capabilities as u16);
        // See https://github.com/RfidResearchGroup/proxmark3/blob/55ef252a5d0d590026a4959a4c1b7a6028d1ad13/include/pm3_cmd.h#L174
        ensure!(response.len() == 13);

        // Check version
        self.send_command_ng(Command::Version, &[])?;
        let (status, cmd, response) = self.receive_response()?;
        ensure!(status == Status::Success as i16);
        ensure!(cmd == Command::Version as u16);
        // https://github.com/RfidResearchGroup/proxmark3/blame/55ef252a5d0d590026a4959a4c1b7a6028d1ad13/client/src/cmdhw.c#L1560
        let mut response = &response[..];
        let _chip_id = response.get_u32_le();
        let _secttion_size = response.get_u32_le();
        let version_str_len = response.get_u32_le();
        let version_str = &response[..version_str_len as usize];

        if self.trace {
            eprintln!(
                "Proxmark3 version: {}",
                String::from_utf8(version_str.to_vec()).unwrap()
            );
        }
        Ok(())
    }

    fn send_command_mix(
        &mut self,
        command: Command,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        data: &[u8],
    ) -> Result<()> {
        let mut payload = BytesMut::with_capacity(1024);
        payload.put_u64_le(arg0);
        payload.put_u64_le(arg1);
        payload.put_u64_le(arg2);
        payload.put_slice(data);
        self.send_command(command as u16, &payload, false)
    }

    fn send_command_ng(&mut self, command: Command, data: &[u8]) -> Result<()> {
        self.send_command(command as u16, data, true)
    }

    fn send_command(&mut self, command: u16, data: &[u8], ng: bool) -> Result<()> {
        assert!(data.len() <= 512);
        // https://github.com/RfidResearchGroup/proxmark3/blob/55ef252a5d0d590026a4959a4c1b7a6028d1ad13/include/pm3_cmd.h#L40-L73
        let mut packet = BytesMut::with_capacity(1024);
        packet.put_u32_le(0x61334d50); // magic 'PM3a'
        packet.put_u16_le(data.len() as u16 | (if ng { 1 << 15 } else { 0 })); // len and NG flag
        packet.put_u16_le(command); // cmd
        packet.put_slice(data); // data
        if self.crc {
            // Add CRC_14443_A
            let crc = Crc::<u16>::new(&CRC_16_ISO_IEC_14443_3_A);
            let crc = crc.checksum(&packet);
            packet.put_u16(crc);
        } else {
            packet.put_u16_le(0x3361);
        }

        self.connection.write(&packet)?;
        Ok(())
    }

    fn receive_response(&mut self) -> Result<(i16, u16, Vec<u8>)> {
        let mut header = [0_u8; 10];
        self.connection.read(&mut header)?;

        // print!("Received ");
        // for byte in header.iter() {
        //     print!(" {:02X} ", byte);
        // }
        // print!(" | ");

        let mut header = &header[..];
        ensure!(header.get_u32_le() == 0x62334d50); // magic
        let len = header.get_u16_le();
        let (len, _ng) = (len & 0x7FFF, len & 0x8000 != 0);
        ensure!(len <= 512);
        let status = header.get_i16_le();
        let cmd = header.get_u16_le();

        // Read data
        let mut data = vec![0_u8; len as usize];
        self.connection.read(&mut data)?;
        // for byte in data.iter() {
        //     print!(" {:02X} ", byte);
        // }
        // print!(" | ");

        // Read CRC
        let mut crc = [0_u8; 2];
        self.connection.read(&mut crc)?;
        // TODO: Check CRC
        // for byte in crc.iter() {
        //     print!(" {:02X} ", byte);
        // }
        // println!("");

        Ok((status, cmd, data))
    }
}

impl NfcReader for Proxmark3 {
    fn connect(&mut self) -> Result<()> {
        // Connect to ISO 14443-A card as reader, keeping the field on.
        // hf 14a reader -k
        // https://github.com/RfidResearchGroup/proxmark3/blob/55ef252a5d0d590026a4959a4c1b7a6028d1ad13/include/mifare.h#L88
        self.send_command_mix(Command::Hf14aReader, 3, 0, 0, &[])?; // 3 = CONNECT | NO_DISCONNECT
        let (status, cmd, response) = self.receive_response()?;
        ensure!(status == Status::Success as i16);
        ensure!(cmd == Command::Ack as u16);
        ensure!(response.len() == 295);
        let mut response = &response[..];
        let _arg0 = response.get_u64_le();
        let _arg1 = response.get_u64_le();
        let _arg2 = response.get_u64_le();
        let (uuid, mut response) = response.split_at(10);
        let uuid_len = response.get_u8();
        let uuid = &uuid[..uuid_len as usize];
        let atqa = response.get_u16_le();
        let sak = response.get_u8();
        let ats_len = response.get_u8();
        let (ats, mut _response) = response.split_at(ats_len as usize);
        if self.trace {
            println!("Card UID: {}", hex::encode(uuid));
            println!("Card ATQA: {}", hex::encode(atqa.to_be_bytes()));
            println!("Card SAK: {}", hex::encode(sak.to_le_bytes()));
            println!("Card ATS: {}", hex::encode(ats));
        }
        Ok(())
    }

    fn disconnect(&mut self) -> Result<()> {
        // Switch field off
        if self.trace {
            eprintln!("Switching field off:");
        }
        self.send_command_mix(Command::Hf14aReader, 1, 0, 0, &[])?;
        let _response = self.receive_response()?;
        Ok(())
    }

    fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        // hf 14a apdu -k -d <apdu>
        if self.trace {
            eprint!("Sending APDU:");
            for byte in apdu.iter() {
                eprint!(" {:02X}", byte);
            }
            eprintln!();
        }
        self.send_command_mix(Command::Hf14aReader, 6, apdu.len() as u64, 0, apdu)?; // 6 = SEND_APDU | NO_DISCONNECT
        let (status, cmd, response) = self.receive_response()?;
        ensure!(status == Status::Success as i16);
        ensure!(cmd == Command::Ack as u16);
        ensure!(response.len() == 512);
        let mut response = &response[..];
        let length = response.get_u64_le();
        let _result = response.get_u64_le();
        let _arg2 = response.get_u64_le();
        ensure!(length >= 2);
        ensure!(length <= 512);
        let data = &response[..length as usize - 2];
        let (data, status) = data.split_at(data.len() - 2);

        if self.trace {
            eprint!("APDU response:");
            for byte in data.iter() {
                eprint!(" {:02X}", byte);
            }
            eprint!(" | ");
            for byte in status.iter() {
                eprint!(" {:02X}", byte);
            }
            eprintln!();
        }
        let status = u16::from_be_bytes([status[0], status[1]]).into();
        if self.trace {
            eprintln!("Status {}", status);
        }
        Ok((status, data.to_vec()))
    }
}
