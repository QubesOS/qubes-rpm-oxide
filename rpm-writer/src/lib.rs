//! RPMv4 package emitter
//!
//! This includes a full RPMv4 package emitter.  It is implemented in Rust to
//! the extent possible, instead of using librpm.

#![cfg_attr(
    ellipsis_inclusive_range_deprecated,
    allow(ellipsis_inclusive_range_patterns)
)]

#[cfg(any(not(any(ellipsis_inclusive_range_deprecated, ellipsis_inclusive_range_allowed)),))]
compile_error!("build script bug");
extern crate openpgp_parser;
extern crate rpm_crypto;
extern crate rpm_parser;
use rpm_parser::TagData;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io::Write;

const RPMTAG_SIG_BASE: u32 = 256;
const RPMSIGTAG_SHA1HEADER: u32 = RPMTAG_SIG_BASE + 13;
const RPMSIGTAG_SHA256HEADER: u32 = RPMTAG_SIG_BASE + 17;
const RPMSIGTAG_RSAHEADER: u32 = RPMTAG_SIG_BASE + 12;
const RPMSIGTAG_PGP: u32 = 1002;
const RPMSIGTAG_MD5: u32 = 1004;

/// What kind of header is this?
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum HeaderKind {
    /// Signature header
    Signature,
    /// Main header
    Main,
}

/// A tag data entry
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HeaderEntry<'a> {
    /// Integer
    Char(&'a [u8]),
    /// Array of [`u8`]
    U8(&'a [u8]),
    /// Array of [`u16`]
    U16(&'a [u16]),
    /// Array of [`u32`]
    U32(&'a [u32]),
    /// Array of [`u64`]
    U64(&'a [u64]),
    /// String
    String(&'a CStr),
    /// Binary blob
    Bin(&'a [u8]),
    /// String array
    StringArray(&'a [&'a CStr]),
    /// Internationalization table
    I18NTable(&'a [&'a CStr]),
}

impl<'a> HeaderEntry<'a> {
    /// The number of bytes required by this entry
    pub fn len(&self) -> usize {
        match self {
            &HeaderEntry::Char(e) | &HeaderEntry::U8(e) | &HeaderEntry::Bin(e) => e.len(),
            &HeaderEntry::U16(e) => e.len() << 1,
            &HeaderEntry::U32(e) => e.len() << 2,
            &HeaderEntry::U64(e) => e.len() << 3,
            &HeaderEntry::String(e) => (*e).to_bytes_with_nul().len(),
            &HeaderEntry::StringArray(e) | &HeaderEntry::I18NTable(e) => {
                e.iter().fold(0, |y, x| x.to_bytes_with_nul().len() + y)
            }
        }
    }
    pub fn alignment(&self) -> usize {
        match self {
            &HeaderEntry::U16(_) => 2,
            &HeaderEntry::U32(_) => 4,
            &HeaderEntry::U64(_) => 8,
            _ => 1,
        }
    }
    pub fn advance_length(&self, len: usize) -> usize {
        let alignment_delta = self.alignment() - 1;
        (len + alignment_delta) & !alignment_delta
    }
    pub fn ty(&self) -> u32 {
        match self {
            &HeaderEntry::Char(_) => 1,
            &HeaderEntry::U8(_) => 2,
            &HeaderEntry::U16(_) => 3,
            &HeaderEntry::U32(_) => 4,
            &HeaderEntry::U64(_) => 5,
            &HeaderEntry::String(_) => 6,
            &HeaderEntry::Bin(_) => 7,
            &HeaderEntry::StringArray(_) => 8,
            &HeaderEntry::I18NTable(_) => 9,
        }
    }
    pub fn write_bytes(&self, w: &mut dyn Write) -> std::io::Result<()> {
        match self {
            &HeaderEntry::Char(e) | &HeaderEntry::U8(e) | &HeaderEntry::Bin(e) => w.write_all(e),
            &HeaderEntry::String(e) => w.write_all(CStr::to_bytes_with_nul(e)),
            &HeaderEntry::StringArray(e) | &HeaderEntry::I18NTable(e) => {
                for &i in e {
                    w.write_all(CStr::to_bytes_with_nul(i))?
                }
                Ok(())
            }
            &HeaderEntry::U16(e) => {
                let mut v = Vec::with_capacity(2 * e.len());
                for &i in e {
                    v.push((i >> 8) as u8);
                    v.push(i as u8);
                }
                w.write_all(&v)
            }
            &HeaderEntry::U32(e) => {
                let mut v = Vec::with_capacity(4 * e.len());
                for &i in e {
                    v.push((i >> 24) as u8);
                    v.push((i >> 16) as u8);
                    v.push((i >> 8) as u8);
                    v.push(i as u8);
                }
                w.write_all(&v)
            }
            &HeaderEntry::U64(e) => {
                let mut v = Vec::with_capacity(8 * e.len());
                for &i in e {
                    v.push((i >> 56) as u8);
                    v.push((i >> 48) as u8);
                    v.push((i >> 40) as u8);
                    v.push((i >> 32) as u8);
                    v.push((i >> 24) as u8);
                    v.push((i >> 16) as u8);
                    v.push((i >> 8) as u8);
                    v.push(i as u8);
                }
                w.write_all(&v)
            }
        }
    }
    pub fn count(&self) -> usize {
        match self {
            &HeaderEntry::String(_) => 1,
            &HeaderEntry::Char(e) => e.len(),
            &HeaderEntry::U8(e) => e.len(),
            &HeaderEntry::U16(e) => e.len(),
            &HeaderEntry::U32(e) => e.len(),
            &HeaderEntry::U64(e) => e.len(),
            &HeaderEntry::Bin(e) => e.len(),
            &HeaderEntry::StringArray(e) => e.len(),
            &HeaderEntry::I18NTable(e) => e.len(),
        }
    }
}

/// A header builder
pub struct HeaderBuilder<'a> {
    kind: HeaderKind,
    data: BTreeMap<u32, HeaderEntry<'a>>,
}

impl<'a> HeaderBuilder<'a> {
    pub fn new(kind: HeaderKind) -> Self {
        Self {
            kind,
            data: Default::default(),
        }
    }
    pub fn push<'b: 'a>(&mut self, tag: u32, header: HeaderEntry<'b>) -> Option<HeaderEntry<'a>> {
        assert!(header.count() < u32::max_value() as _, "overflow");
        self.data.insert(tag, header)
    }
    fn len(&self) -> usize {
        self.data
            .iter()
            .fold(16, |len, entry| entry.1.advance_length(len) + entry.1.len())
    }
    pub fn emit(&self, t: &mut dyn Write) -> std::io::Result<()> {
        let (dl, il) = (self.len(), self.data.len() + 1);
        let res = [
            TagData::new(0x8eade801, 0, il as _, dl as _),
            TagData::new(
                match self.kind {
                    HeaderKind::Signature => 62,
                    HeaderKind::Main => 63,
                },
                7,
                (dl - 16) as _,
                16,
            ),
        ];
        t.write_all(TagData::as_bytes(&res))?;
        let mut rdl1 = 0;
        for entry in self.data.iter() {
            let offset = entry.1.advance_length(rdl1);
            t.write_all(TagData::as_bytes(&[TagData::new(
                *entry.0,
                entry.1.ty(),
                offset as _,
                entry.1.count() as _,
            )]))?;
            rdl1 = offset + entry.1.len();
        }
        let mut rdl = 16;
        for entry in self.data.iter() {
            let offset = entry.1.advance_length(rdl);
            t.write_all(&[0, 0, 0, 0, 0, 0, 0, 0][..offset - rdl])?;
            entry.1.write_bytes(t)?;
            rdl = offset + entry.1.len()
        }
        assert_eq!(rdl1 + 16, rdl);
        assert_eq!(rdl, dl);
        t.write_all(TagData::as_bytes(&[TagData::new(
            res[1].tag(),
            7,
            (-16i32 * il as i32) as u32,
            16,
        )]))?;
        Ok(())
    }
}

fn emit_header(
    &rpm_parser::VerifyResult {
        ref main_header,
        ref header_payload_sig,
        ref header_sig,
        ref main_header_bytes,
        ref main_header_sha1_hash,
        ref main_header_sha256_hash,
        ref header_payload_weak_digest,
    }: &rpm_parser::VerifyResult,
    mut dest: Option<&mut dyn std::io::Write>,
    _allow_weak_hashes: openpgp_parser::AllowWeakHashes,
    _token: rpm_crypto::InitToken,
) -> std::io::Result<()> {
    let dest = dest.as_mut().expect("we always pass a stream; qed");
    let magic_offset = 96;
    let mut hdr = HeaderBuilder::new(HeaderKind::Signature);
    hdr.push(
        RPMSIGTAG_SHA1HEADER,
        HeaderEntry::String(
            CStr::from_bytes_with_nul(&main_header_sha1_hash)
                .expect("RPM NUL-terminates its hex data"),
        ),
    );
    hdr.push(
        RPMSIGTAG_SHA256HEADER,
        HeaderEntry::String(
            CStr::from_bytes_with_nul(&main_header_sha256_hash)
                .expect("RPM NUL-terminates its hex data"),
        ),
    );
    hdr.push(RPMSIGTAG_RSAHEADER, HeaderEntry::Bin(&*header_sig));
    if let &Some(ref sig) = header_payload_sig {
        hdr.push(RPMSIGTAG_PGP, HeaderEntry::Bin(sig));
    }
    if let &Some(ref weak_digest) = header_payload_weak_digest {
        hdr.push(RPMSIGTAG_MD5, HeaderEntry::Bin(weak_digest));
    }
    hdr.push(1007, HeaderEntry::U32(&[0]));
    hdr.push(1000, HeaderEntry::U32(&[0]));
    let mut out_data = vec![0; magic_offset];
    out_data[..magic_offset].copy_from_slice(&main_header.lead());
    hdr.emit(&mut out_data).expect("writes to a vec never fail");
    let fixup = (out_data.len() + 7 & !7) - out_data.len();
    out_data.extend_from_slice(&[0u8; 7][..fixup]);
    #[cfg(debug_assertions)]
    rpm_parser::load_signature(&mut &out_data[magic_offset..], _allow_weak_hashes, _token).unwrap();
    dest.write_all(&out_data)?;
    dest.write_all(&main_header_bytes)
}

pub fn canonicalize_package(
    allow_old_pkgs: bool,
    preserve_old_signature: bool,
    token: rpm_crypto::InitToken,
    source: &mut dyn std::io::Read,
    dest: &mut dyn std::io::Write,
    allow_weak_hashes: openpgp_parser::AllowWeakHashes,
    keyring: &rpm_crypto::transaction::RpmKeyring,
) -> std::io::Result<rpm_parser::VerifyResult> {
    let mut emit_header: &mut dyn FnMut(
        &rpm_parser::VerifyResult,
        Option<&mut dyn std::io::Write>,
    ) -> std::io::Result<()> = &mut |x, y| emit_header(x, y, allow_weak_hashes, token);
    // Ignore the lead
    let _ = rpm_parser::read_lead(source)?;
    // Read the signature header
    let mut sig_header = rpm_parser::load_signature(source, allow_weak_hashes, token)?;
    rpm_parser::verify_package(
        source,
        &mut sig_header,
        keyring,
        allow_old_pkgs,
        preserve_old_signature,
        token,
        Some(&mut emit_header),
        Some(dest),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let mut builder = HeaderBuilder::new(HeaderKind::Signature);
        let entry = HeaderEntry::String(
            CStr::from_bytes_with_nul(&b"0000000000000000000000000000000000000000\0"[..]).unwrap(),
        );
        assert!(builder.push(256 + 13, entry).is_none());
        assert_eq!(builder.push(256 + 13, entry), Some(entry));
        assert!(builder.push(1005, HeaderEntry::Bin(&b"abc"[..])).is_none());
        builder.emit(&mut vec![]).unwrap()
    }
}
