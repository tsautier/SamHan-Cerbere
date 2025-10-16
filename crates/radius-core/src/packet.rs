//! radius-core::packet — minimal RADIUS header/types (skeleton)
use anyhow::{bail, Result};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    // ... other codes not implemented here
}

impl Code {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Code::AccessRequest),
            2 => Some(Code::AccessAccept),
            3 => Some(Code::AccessReject),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub code: Code,
    pub identifier: u8,
    pub length: u16,
    pub authenticator: [u8; 16],
}

impl Header {
    pub const LEN: usize = 20;

    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() < Self::LEN {
            bail!("radius header too short");
        }
        let code = Code::from_u8(buf[0]).ok_or_else(|| anyhow::anyhow!("unsupported code"))?;
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]);
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&buf[4..20]);

        if length as usize > buf.len() {
            bail!("declared length larger than buffer");
        }
        let rest = &buf[20..length as usize];
        Ok((Self { code, identifier, length, authenticator }, rest))
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code as u8);
        out.push(self.identifier);
        out.extend_from_slice(&self.length.to_be_bytes());
        out.extend_from_slice(&self.authenticator);
    }
}
