//! Generic RPM header parsing routines
//!
//! This contains code common to signature and main headers.

#![forbid(unsafe_code)]

use super::super::ffi::TagType;
use super::super::TagData;
use super::u32_be_bytes;
use openpgp_parser::Reader;
use std;
use std::io::{Error, ErrorKind, Read, Result};

pub const RPM_HDRMAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00];

/// A parsed RPM header
pub struct Header {
    /// The index
    pub index: Vec<TagData>,
    /// The data
    pub data: Vec<u8>,
}

pub fn parse_header_magic<'a>(data: &[u8; 16]) -> Result<(u32, u32)> {
    if data[..8] != RPM_HDRMAGIC[..] {
        return Err(Error::new(ErrorKind::InvalidData, "wrong header magic"));
    }
    let index_length = u32_be_bytes(&data[8..12]);
    let data_length = u32_be_bytes(&data[12..16]);
    fail_if!(index_length < 2, "index must have more than a region");
    fail_if!(index_length > 0xFFFF, "index too long");
    fail_if!(data_length < 16, "data cannot hold a region");
    fail_if!(data_length >= 256 * 1024 * 1024, "data too long");
    Ok((index_length, data_length))
}

pub fn read_header(r: &mut Read) -> Result<(u32, u32)> {
    #[cfg(any())]
    let _: [u8; 0] = [0u8; if size_of!(usize) >= size_of!(u32) {
        0
    } else {
        1
    }];
    let (index_length, data_length) = {
        let mut magic = [0; 16];
        r.read_exact(&mut magic)?;
        parse_header_magic(&magic)?
    };
    Ok((index_length as _, data_length as _))
}

const TAG_REGISTRY: &[(TagType, usize, Option<usize>)] = &[
    (TagType::Char, 0, Some(1)),
    (TagType::Int8, 0, Some(1)),
    (TagType::Int16, 1, Some(2)),
    (TagType::Int32, 3, Some(4)),
    (TagType::Int64, 7, Some(8)),
    (TagType::String, 0, None),
    (TagType::Bin, 0, Some(1)),
    (TagType::StringArray, 0, None),
    (TagType::I18NString, 0, None),
];

pub(super) fn load_header<'a>(
    r: &mut Read,
    region_tag: u32,
    cb: &mut FnMut(TagType, &TagData, &[u8]) -> Result<()>,
) -> Result<Header> {
    let (index_length, data_length) = read_header(r)?;
    let mut index = vec![Default::default(); index_length as _];
    let mut data = vec![0; data_length as _];
    {
        r.read_exact(TagData::as_bytes_mut(&mut index))?;
        r.read_exact(&mut data)?;
        let ref region = index[0];
        let region_offset = data_length as usize - 16;
        if region.count() != 16
            || region.ty() != TagType::Bin as _
            || region.offset() as usize != region_offset
        {
            bad_data!("bad region trailer location {:?}", region)
        }
        let mut last_tag = region.tag();
        if last_tag != region_tag {
            bad_data!("bad region kind {}, expected {}", last_tag, region_tag)
        };
        {
            let mut trailer_array = [TagData::default()];
            TagData::as_bytes_mut(&mut trailer_array).copy_from_slice(&data[region_offset as _..]);
            let trailer = trailer_array[0];
            let trailer_offset = trailer.offset() as i32;
            if last_tag != trailer.tag() {
                bad_data!("bad region trailer tag {}", trailer.tag())
            } else if TagType::Bin as u32 != trailer.ty() {
                bad_data!("bad region trailer type {}", trailer.ty())
            } else if 16 != trailer.count() {
                bad_data!("bad region trailer count {}", trailer.count())
            } else if trailer_offset > 0 || trailer_offset + (16 * index_length) as i32 != 0 {
                bad_data!("bad region trailer offset {}", trailer_offset)
            }
        }
        let mut cursor = 0;
        let mut reader = Reader::new(&data[..region_offset]);
        last_tag = 99;
        for entry in &index[1..] {
            let tag = entry.tag();
            fail_if!(tag <= last_tag, "entries not sorted");
            let &(ty, align, size) = match TAG_REGISTRY.get(entry.ty().wrapping_sub(1) as usize) {
                None => bad_data!("Entry {:?} has an invalid type {}", entry, entry.ty()),
                Some(s) => s,
            };
            let offset = entry.offset();
            fail_if!(offset > data_length, "Entry {:?} has bad offset", offset);
            let offset = offset as usize;
            let count = entry.count();
            // data_length is less than 256 * 1024 * 1024, so this is enough to
            // ensure no overflows when multiplying “count” by the data size
            if count == 0 || count >= data_length {
                bad_data!("Entry {:?} has invalid count", entry)
            }
            let count = count as usize;
            if offset & align != 0 {
                bad_data!("Entry {:?} is not properly aligned", entry)
            }
            fail_if!(offset < cursor, "Entry {:?} overlaps previous entry", entry);
            let padding = offset - cursor;
            if padding > align {
                bad_data!("Entry {:?} has too much padding ({})", entry, padding)
            }
            if reader.get_bytes(padding)? != &[0u8; 8][..padding] {
                bad_data!("Entry {:?} has padding that is not zeroed", entry)
            }
            cursor = offset;
            let buf = match size {
                Some(s) => reader.get_bytes(s * count)?,
                None => {
                    if ty == TagType::String && count != 1 {
                        bad_data!("Entry {:?} is a string with nonunit count", entry)
                    }
                    let mut dup_count = count;
                    let mut len = 0;
                    for &i in reader.as_untrusted_slice() {
                        len += 1;
                        if i == 0 {
                            dup_count -= 1;
                            if dup_count == 0 {
                                break;
                            }
                        }
                    }
                    if dup_count != 0 {
                        bad_data!("Entry {:?} is a too long string array", entry)
                    }
                    let r = reader.get_bytes(len).expect("length is in bounds; qed");
                    match std::str::from_utf8(r) {
                        Ok(_) => r,
                        Err(e) => bad_data!("String entry is not valid UTF-8: {}", e),
                    }
                }
            };
            cursor += buf.len();
            cb(ty, entry, buf)?
        }
        fail_if!(reader.len() != 0, "{} bytes of trailing junk", reader.len());
    }
    Ok(Header { index, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_header_magic() {
        assert_eq!(
            parse_header_magic(&[0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0])
                .unwrap(),
            (0x100, 0x100)
        );
        assert_eq!(
            parse_header_magic(&[0x8e, 0xad, 0xe8, 0x01, 0, 3, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0])
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }
}
