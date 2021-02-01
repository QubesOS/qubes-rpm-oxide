//! Routines for parsing RPM package leads
//!
//! The lead is a 96-byte data structure at the start of every RPM package.
//! Most of its functionality has been replaced by the header.

use std::io::{Read, Result};
use std::mem::{size_of, zeroed};

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct RPMLead {
    pub magic: [u8; 4],
    pub major: u8,
    pub minor: u8,
    pub ty: u16,
    pub archnum: u16,
    pub name: [u8; 65],
    null: u8,
    pub osnum: u16,
    pub signature_type: u16,
    pub reserved: [u8; 16],
}

pub fn read_lead(r: &mut dyn Read) -> Result<RPMLead> {
    let _: [u8; 96] = [0u8; size_of::<RPMLead>()];
    // FIXME replace with safe code
    let mut lead = unsafe {
        let mut lead: RPMLead = zeroed();
        let ptr = &mut lead as *mut RPMLead as *mut u8;
        r.read_exact(std::slice::from_raw_parts_mut(ptr, size_of::<RPMLead>()))?;
        lead
    };
    lead.ty = u16::from_be(lead.ty);
    lead.archnum = u16::from_be(lead.archnum);
    lead.osnum = u16::from_be(lead.osnum);
    lead.signature_type = u16::from_be(lead.signature_type);
    fail_if!(lead.magic != [0xed, 0xab, 0xee, 0xdb], "not an RPM package");
    fail_if!(
        lead.major != 3,
        "unsupported RPM package version {}",
        lead.major
    );
    fail_if!(lead.ty > 1, "unknown package type {}", lead.ty);
    let mut seen_nul = false;
    for &i in &lead.name {
        match i {
            b'A'..=b'Z' | b'a'..=b'z' | b'.' | b'-' | b'_' | b'+' | b'~' | b'0'..=b'9'
                if !seen_nul => {}
            b'\0' => seen_nul = true,
            _ => bad_data!("invalid package name"),
        }
    }
    std::str::from_utf8(&lead.name).expect("already checked above");
    fail_if!(lead.null != 0, "package name not NUL-terminated");
    fail_if!(
        lead.signature_type != 5,
        "unsupported signature type {}",
        lead.signature_type
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
