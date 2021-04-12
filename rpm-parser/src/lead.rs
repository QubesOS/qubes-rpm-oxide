//! Routines for parsing RPM package leads
//!
//! The lead is a 96-byte data structure at the start of every RPM package.
//! Most of its functionality has been replaced by the header.

use std;
use std::io::{Read, Result};
use std::mem::{size_of, zeroed};

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

impl RPMLead {
    pub(crate) fn new(ty: bool, archnum: u16, osnum: u16, name: &[u8]) -> Self {
        let mut name_dup = [0u8; 66];
        let bytes_to_copy = name.len().min(65);
        name_dup[..bytes_to_copy].copy_from_slice(&name[..bytes_to_copy]);
        Self {
            magic: [0xed, 0xab, 0xee, 0xdb],
            major: 3,
            minor: 0,
            ty: (ty as u16).to_be(),
            archnum: archnum.to_be(),
            name: name_dup,
            osnum: osnum.to_be(),
            signature_type: 5u16.to_be(),
            reserved: [0; 16],
        }
    }

    pub fn ty(&self) -> u16 {
        self.ty.to_be()
    }

    pub fn archnum(&self) -> u16 {
        self.archnum.to_be()
    }

    pub fn osnum(&self) -> u16 {
        self.osnum.to_be()
    }

    pub fn signature_type(&self) -> u16 {
        self.signature_type.to_be()
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..]
    }

    pub fn as_slice(self) -> [u8; 96] {
        // FIXME use safe code instead
        unsafe { std::mem::transmute(self) }
    }
}

pub fn read_lead(r: &mut Read) -> Result<RPMLead> {
    let _: [u8; 96] = [0u8; size_of::<RPMLead>()];
    // FIXME replace with safe code
    let lead = unsafe {
        let mut lead: RPMLead = zeroed();
        let ptr = &mut lead as *mut RPMLead as *mut u8;
        r.read_exact(std::slice::from_raw_parts_mut(ptr, size_of::<RPMLead>()))?;
        lead
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
    #[should_panic = "not an RPM package"]
    fn rejects_bad_magic() {
        read_lead(&mut &[0u8; 96][..]).unwrap();
    }
    #[test]
    #[should_panic = "unsupported RPM package version 5"]
    fn rejects_bad_version() {
        let mut s = [0u8; 96];
        s[..5].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 5]);
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic = "{ kind: InvalidData, error: \"unknown package type 3\" }"]
    fn rejects_non_zeroed_reserved() {
        let mut s = [0u8; 96];
        s[..8].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 3]);
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic = "{ kind: InvalidData, error: \"invalid package name"]
    fn rejects_non_utf8_name() {
        let mut s = [0xFFu8; 96];
        s[..8].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0]);
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic = "{ kind: InvalidData, error: \"invalid package name"]
    fn rejects_invalid_char_name() {
        let mut s = [0xFFu8; 96];
        s[..8].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0]);
        s[8] = 0;
        s[11] = b'a';
        s[12..78].copy_from_slice(&[0u8; 66]);
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic = "{ kind: InvalidData, error: \"unsupported signature type 0\" }"]
    fn rejects_wrong_signature_version() {
        let mut s = [0x0u8; 96];
        s[..8].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0]);
        s[8] = 0;
        s[10] = b'a';
        read_lead(&mut &s[..]).unwrap();
    }
    #[test]
    #[should_panic = "{ kind: InvalidData, error: \"reserved bytes not zeroed\" }"]
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
