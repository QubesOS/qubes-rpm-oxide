//! RPMv4 package emitter
//!
//! This includes a full RPMv4 package emitter.  It is implemented in Rust to
//! the extent possible, instead of using librpm.

extern crate rpm_parser;
use rpm_parser::TagData;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io::Write;

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
    pub fn write_bytes(&self, w: &mut Write) -> std::io::Result<()> {
        match self {
            &HeaderEntry::Char(e) | &HeaderEntry::U8(e) | &HeaderEntry::Bin(e) => w.write_all(e),
            &HeaderEntry::String(e) => w.write_all(CStr::to_bytes_with_nul(e)),
            &HeaderEntry::StringArray(e) | &HeaderEntry::I18NTable(e) => {
                for &i in e {
                    w.write_all(CStr::to_bytes_with_nul(i))?
                }
                Ok(())
            }
            _ => unimplemented!(),
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
    pub fn emit(&self, t: &mut Write) -> std::io::Result<()> {
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
