//! Routines for parsing RPM package leads
//!
//! The lead is a 96-byte data structure at the start of every RPM package.
//! Most of its functionality has been replaced by the header.

use std::io::{Read, Result};
use std::mem::size_of;

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct RPMLead {
    magic: [u8; 4],
    major: u8,
    minor: u8,
    ty: u16,
    archnum: u16,
    name: [u8; 66],
    osnum: u16,
    signature_type: u16,
    reserved: [u8; 16],
}

fn read_be_u16(buf: &[u8]) -> u16 {
    (buf[0] as u16) << 8 | buf[1] as u16
}

fn write_be_u16(buf: &mut [u8], s: u16) {
    buf[0] = (s >> 8) as u8;
    buf[1] = s as u8
}

impl RPMLead {
    pub(crate) fn new(ty: bool, archnum: u16, osnum: u16, name: &[u8]) -> Self {
        let mut name_dup = [0u8; 66];
        let bytes_to_copy = name.len().min(65);
        name_dup[..bytes_to_copy].copy_from_slice(&name[..bytes_to_copy]);
        Self {
            magic: [0xed, 0xab, 0xee, 0xdb],
            major: 3,
            minor: 0,
            ty: (ty as u16),
            archnum: archnum,
            name: name_dup,
            osnum: osnum,
            signature_type: 5u16,
            reserved: [0; 16],
        }
    }

    pub fn ty(&self) -> u16 {
        self.ty
    }

    pub fn archnum(&self) -> u16 {
        self.archnum
    }

    pub fn osnum(&self) -> u16 {
        self.osnum
    }

    pub fn signature_type(&self) -> u16 {
        self.signature_type
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..]
    }

    pub fn as_slice(self) -> [u8; 96] {
        let mut buf = [0u8; 96];
        buf[..4].copy_from_slice(&self.magic);
        buf[4] = self.major;
        buf[5] = self.minor;
        write_be_u16(&mut buf[6..8], self.ty);
        write_be_u16(&mut buf[8..10], self.archnum);
        buf[10..76].copy_from_slice(&self.name);
        write_be_u16(&mut buf[76..78], self.osnum);
        write_be_u16(&mut buf[78..80], self.signature_type);
        buf
    }

    fn from_array(buf: [u8; 96]) -> Self {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[..4]);
        let major = buf[4];
        let minor = buf[5];
        let ty = read_be_u16(&buf[6..8]);
        let archnum = read_be_u16(&buf[8..10]);
        let mut name = [0u8; 66];
        name.copy_from_slice(&buf[10..76]);
        let osnum = read_be_u16(&buf[76..78]);
        let signature_type = read_be_u16(&buf[78..80]);
        let mut reserved = [0u8; 16];
        reserved.copy_from_slice(&buf[80..]);
        Self {
            magic,
            major,
            minor,
            ty,
            archnum,
            name,
            osnum,
            signature_type,
            reserved,
        }
    }
}

pub fn read_lead(r: &mut Read) -> Result<RPMLead> {
    let lead = {
        let mut s: [u8; 96] = [0u8; size_of::<RPMLead>()];
        r.read_exact(&mut s[..])?;
        RPMLead::from_array(s)
    };
    fail_if!(lead.magic != [0xed, 0xab, 0xee, 0xdb], "not an RPM package");
    fail_if!(
        lead.major != 3 || lead.minor != 0,
        "unsupported RPM package version {}.{}",
        lead.major,
        lead.minor
    );
    fail_if!(lead.ty() > 1, "unknown package type {}", lead.ty());
    let mut seen_nul = false;
    for &i in &lead.name[..] {
        match i {
            b'A'...b'Z' | b'a'...b'z' | b'.' | b'-' | b'_' | b'+' | b'~' | b':' | b'0'...b'9'
                if !seen_nul => {}
            b'\0' => seen_nul = true,
            _ => bad_data!("invalid package name"),
        }
    }
    fail_if!(!seen_nul, "package name not NUL-terminated");
    fail_if!(
        lead.signature_type() != 5,
        "unsupported signature type {}",
        lead.signature_type()
    );
    fail_if!(
        lead.reserved != <[u8; 16]>::default(),
        "reserved bytes not zeroed"
    );
    Ok(lead)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[should_panic(expected = "not an RPM package")]
    fn rejects_bad_magic() {
        read_lead(&mut &[0u8; 96][..]).unwrap();
    }
    #[test]
    #[should_panic(expected = "\"unsupported RPM package version 5.0\"")]
    fn rejects_bad_version() {
        let mut s = [0u8; 96];
        s[..5].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 5]);
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic(expected = "\"unknown package type 3\"")]
    fn rejects_non_zeroed_reserved() {
        let mut s = [0u8; 96];
        s[..8].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 3]);
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic(expected = "\"invalid package name\"")]
    fn rejects_non_utf8_name() {
        let mut s = [0xFFu8; 96];
        s[..8].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0]);
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic(expected = "\"invalid package name\"")]
    fn rejects_invalid_char_name() {
        let mut s = [0xFFu8; 96];
        s[..8].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0]);
        s[8] = 0;
        s[11] = b'a';
        s[12..78].copy_from_slice(&[0u8; 66]);
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic(expected = "\"unsupported signature type 0\"")]
    fn rejects_wrong_signature_version() {
        let mut s = [0x0u8; 96];
        s[..8].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0]);
        s[8] = 0;
        s[10] = b'a';
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic(expected = "\"reserved bytes not zeroed\"")]
    fn rejects_bad_padding() {
        let mut s = [0x0u8; 96];
        s[..8].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0]);
        s[8] = 0;
        s[10] = b'a';
        s[79] = 5;
        s[85] = 1;
        read_lead(&mut &s[..]).unwrap();
    }
}
