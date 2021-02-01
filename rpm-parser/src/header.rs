//! Functions for parsing RPM headers
//!
//! RPM headers use an undocumented binary format.
#[deny(warnings)]
use super::ffi::{tag_type, Signature, TagType};
use openpgp_parser::buffer::Reader;
use std::convert::TryInto;
use std::io::{Error, ErrorKind, Read, Result};
const RPM_HDRMAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00];

pub fn parse_header_magic<'a>(data: &[u8; 16]) -> Result<(u32, u32)> {
    if data[..8] != RPM_HDRMAGIC[..] {
        return Err(Error::new(ErrorKind::InvalidData, "wrong header magic"));
    }
    let index_length = u32::from_be_bytes(data[8..12].try_into().expect("correct number of bytes"));
    let data_length = u32::from_be_bytes(data[12..].try_into().expect("correct number of bytes"));
    fail_if!(index_length < 2, "index must have more than a region");
    fail_if!(index_length > 0xFFFF, "index too long");
    fail_if!(data_length < 16, "data cannot hold a region");
    fail_if!(data_length >= 256 * 1024 * 1024, "data too long");
    Ok((index_length, data_length))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Flags {
    None,
    HeaderSig,
    HeaderPayloadSig,
    HeaderDigest,
    HeaderPayloadDigest,
    PayloadDigest,
    Zeroed,
}

macro_rules! stuff {
    ($($(#[doc = $e:expr])+($a:expr,$b:expr,$c:expr,$d:expr$(,)?)),*$(,)?) => {
        [
            $((($a, $b), $c, $d, concat!($($e),+))),*
        ]
    }
}

static RPM_SIG_TAGS: &'static [((u32, TagType), Option<usize>, Flags, &'static str)] = &stuff![
    /// Header signature
    (256 + 11, TagType::Bin, None, Flags::HeaderSig),
    /// Header signature
    (256 + 12, TagType::Bin, None, Flags::HeaderSig),
    /// Header SHA1 hash
    (256 + 13, TagType::String, Some(41), Flags::HeaderDigest),
    /// 64 bit Header+Payload size
    (256 + 14, TagType::Int64, Some(8), Flags::None),
    /// 64 bit uncompressed payload size
    (256 + 15, TagType::Int64, Some(8), Flags::None),
    /// Hex SHA256 hash of the header
    (256 + 17, TagType::String, Some(65), Flags::HeaderDigest),
    /// 32 bit Header+Payload size
    (1000, TagType::Int32, Some(4), Flags::None),
    /// Header+Payload GPG signature
    (1002, TagType::Bin, None, Flags::HeaderPayloadSig),
    /// Hex MD5 hash
    (1004, TagType::Bin, Some(16), Flags::HeaderPayloadDigest),
    /// Header+Payload GPG signature
    (1005, TagType::Bin, None, Flags::HeaderPayloadSig),
    /// 32 bit uncompressed payload size
    (1007, TagType::Int32, Some(4), Flags::None),
    /// Padding (must be zeroed)
    (1008, TagType::Bin, None, Flags::Zeroed),
];

mod tag {
    /// An RPM tag data entry
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
    #[repr(C)]
    pub struct TagData {
        tag: u32,
        ty: u32,
        offset: u32,
        count: u32,
    }

    impl TagData {
        /// Cast a slice of [`TagData`] to a slice of `u8`, without copying
        pub fn as_bytes<'a>(slice: &'a [Self]) -> &'a [u8] {
            // Static assertions
            let _: [u8; 16] = [0u8; size_of!(Self)];
            let _: [u8; 4] = [0u8; size_of!(u32)];
            let _: [u8; align_of!(u32)] = [0u8; align_of!(Self)];
            // we now know that `TagData` cannot have any padding
            unsafe {
                std::slice::from_raw_parts(
                    slice.as_ptr() as *const u8,
                    slice.len() * size_of!(Self),
                )
            }
        }
        /// Cast a mutable slice of [`TagData`] to a mutable slice of `u8`, without copying
        ///
        /// This is safe:
        ///
        /// ```compile_fail
        /// # use rpm_parser::header::TagData;
        /// let mut i = [TagData::default()];
        /// let j = TagData::as_bytes_mut(&mut i);
        /// i[0];
        /// j[0]; // won’t compile
        /// ```
        pub fn as_bytes_mut<'a>(slice: &'a mut [Self]) -> &'a mut [u8] {
            // Static assertions
            let _: [u8; 16] = [0u8; size_of!(Self)];
            let _: [u8; 4] = [0u8; size_of!(u32)];
            let _: [u8; align_of!(u32)] = [0u8; align_of!(Self)];
            // we now know that `TagData` cannot have any padding
            unsafe {
                std::slice::from_raw_parts_mut(
                    slice.as_mut_ptr() as *mut u8,
                    slice.len() * size_of!(Self),
                )
            }
        }
    }

    impl TagData {
        /// The tag
        pub fn tag(&self) -> u32 {
            u32::from_be(self.tag)
        }
        /// The type
        pub fn ty(&self) -> u32 {
            u32::from_be(self.ty)
        }
        /// The offset
        pub fn offset(&self) -> u32 {
            u32::from_be(self.offset)
        }
        /// The count
        pub fn count(&self) -> u32 {
            u32::from_be(self.count)
        }
    }
}

pub use tag::TagData;

/// A parsed RPM header
#[non_exhaustive]
pub struct Header {
    /// The index
    pub index: Vec<TagData>,
    /// The data
    pub data: Vec<u8>,
}

/// A parsed RPM signature header
#[non_exhaustive]
pub struct SignatureHeader {
    /// The header
    pub header: Header,
    /// The header signature, if any
    pub header_signature: Option<Signature>,
    /// The header+payload signature, if any
    pub header_payload_signature: Option<Signature>,
}

/// A parsed RPM immutable header
pub struct ImmutableHeader {
    /// The  header
    pub header: Header,
    /// The payload digest algorithm, if any
    pub payload_digest_algorithm: Option<i32>,
    /// The payload digest, if any
    pub payload_digest: Option<Vec<u8>>,
}

pub fn read_header(r: &mut dyn Read) -> Result<(u32, u32)> {
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

/// Check that a `Reader` is a properly formatted hex string.  Assert that
/// it is NUL-terminated.
fn check_hex(body: Reader<'_>) -> Result<()> {
    let (len, untrusted_body) = (body.len(), body.as_untrusted_slice());
    fail_if!(len & 1 == 0, "hex length not even");
    assert_eq!(
        untrusted_body[len - 1],
        0,
        "missing NUL termination not caught earlier"
    );
    for &i in &untrusted_body[..len - 1] {
        match i {
            b'a'..=b'f' | b'0'..=b'9' => (),
            _ => bad_data!("bad hex"),
        }
    }
    Ok(())
}

pub fn load_signature(r: &mut dyn Read) -> Result<SignatureHeader> {
    let mut header_signature = None;
    let mut header_payload_signature = None;
    if cfg!(test) {
        let mut s = RPM_SIG_TAGS[0].0;
        for i in &RPM_SIG_TAGS[1..] {
            assert!(i.0 > s, "{:?} not greater than {:?}", i.0, s);
            s = i.0;
        }
    }
    let mut cb = |ty: TagType, tag_data: &TagData, body: Reader<'_>| {
        let tag = tag_data.tag();
        let (_, size, flags, _) = match RPM_SIG_TAGS.binary_search_by_key(&(tag, ty), |x| x.0) {
            Ok(e) => RPM_SIG_TAGS[e],
            Err(_) => bad_data!("bogus tag type {:?} for tag {}", ty, tag),
        };
        if let Some(size) = size {
            if size != body.len() {
                bad_data!(
                    "BAD: tag size {} for tag {} and type {:?}",
                    body.len(),
                    tag,
                    ty
                )
            }
        }
        match flags {
            Flags::HeaderPayloadDigest | Flags::None => Ok(()),
            Flags::Zeroed => Ok(for &i in body.as_untrusted_slice() {
                fail_if!(i != 0, "padding not zeroed")
            }),
            Flags::HeaderDigest | Flags::PayloadDigest => {
                // our lengths include the terminating NUL
                check_hex(body)
            }
            Flags::HeaderSig | Flags::HeaderPayloadSig => {
                let sig = match Signature::parse(body, 0) {
                    Ok(e) => e,
                    Err(e) => bad_data!("bad OpenPGP signature: {:?}", e),
                };
                match std::mem::replace(
                    if flags == Flags::HeaderSig {
                        &mut header_signature
                    } else {
                        &mut header_payload_signature
                    },
                    Some(sig),
                ) {
                    Some(_) => bad_data!("more than one signature of the same type"),
                    None => Ok(()),
                }
            }
        }
    };
    let header = load_header(r, HeaderType::Signature, &mut cb)?;
    let remainder = header.data.len() & 7;
    if remainder != 0 {
        let mut s = [0u8; 7];
        let s = &mut s[..8 - remainder];
        r.read_exact(s)?;
        for &mut i in s {
            if i != 0 {
                bad_data!("nonzero padding after signature header")
            }
        }
    }
    Ok(SignatureHeader {
        header,
        header_signature,
        header_payload_signature,
    })
}

pub fn load_immutable(r: &mut dyn Read) -> Result<ImmutableHeader> {
    let mut payload_digest_algorithm = None;
    let mut payload_digest: Option<Vec<u8>> = None;
    let mut cb = |ty: TagType, tag_data: &TagData, body: Reader<'_>| -> Result<()> {
        let tag = tag_data.tag();
        fail_if!(tag < 1000 && tag != 100, "signature in immutable header");
        fail_if!(tag > 0x7FFF, "type too large");
        match tag_type(tag) {
            Some((t, is_array)) if t == ty => {
                if !is_array && tag_data.count() != 1 {
                    bad_data!("Non-array tag {} with count {}", tag, tag_data.count())
                }
            }
            None => bad_data!("invalid tag {} in immutable header", tag),
            Some((t, _)) => {
                bad_data!(
                    "wrong type in immutable header: expected {:?} but got {:?}",
                    t,
                    ty
                )
            }
        }
        if tag == 5093 {
            // payload digest algorithm
            assert_eq!(ty, TagType::Int32);
            let alg = i32::from_be_bytes(match body.as_untrusted_slice().try_into() {
                Err(_) => bad_data!("wrong length"), // RPM might make this an array in the future
                Ok(e) => e,
            });
            let hash_len =
                openpgp_parser::packet_types::check_hash_algorithm(alg).map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("bad algorithm {}: {:?}", alg, e),
                    )
                })?;
            if super::ffi::rpm_hash_len(alg) != hash_len.into() {
                bad_data!("Unsupported hash algorithm {}", alg)
            }
            match payload_digest {
                None => bad_data!("no payload digest"),
                Some(ref e) if e.len() == (2 * hash_len + 1).into() => {}
                Some(_) => bad_data!("wrong payload digest length"),
            }
            payload_digest_algorithm = Some(alg)
        } else if tag == 5092 || tag == 5097 {
            // payload digest
            fail_if!(tag_data.count() != 1, "more than one payload digest?");
            check_hex(body.clone())?;
            if tag == 5092 {
                assert!(payload_digest.is_none(), "duplicate tags rejected earlier");
                payload_digest = Some(body.as_untrusted_slice().to_owned())
            }
        }
        Ok(())
    };
    let header = load_header(r, HeaderType::Immutable, &mut cb)?;
    Ok(ImmutableHeader {
        header,
        payload_digest_algorithm,
        payload_digest,
    })
}

pub enum HeaderType {
    Signature,
    Immutable,
}

fn load_header<'a>(
    r: &mut dyn Read,
    region_type: HeaderType,
    cb: &mut dyn FnMut(TagType, &TagData, Reader<'_>) -> Result<()>,
) -> Result<Header> {
    let (index_length, data_length) = read_header(r)?;
    let mut index = vec![Default::default(); index_length as _];
    let mut data = vec![0; data_length as _];
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
    let mut last_tag = match region_type {
        HeaderType::Signature => 62,
        HeaderType::Immutable => 63,
    };
    if last_tag != region.tag() {
        bad_data!("bad region kind {}, expected {}", region.tag(), last_tag,)
    };
    {
        let mut trailer_array = [TagData::default()];
        TagData::as_bytes_mut(&mut trailer_array).copy_from_slice(&data[region_offset as _..]);
        let [trailer] = trailer_array;
        let trailer_offset = trailer.offset() as i32;
        if last_tag != trailer.tag()
            || TagType::Bin as u32 != trailer.ty()
            || 16 != trailer.count()
            || trailer_offset > 0
            || trailer_offset + (16 * index_length) as i32 != 0
        {
            bad_data!("bad region trailer {:?}", trailer)
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
        if reader.get(padding)? != Reader::new(&[0u8; 8][..padding]) {
            bad_data!("Entry {:?} has padding that is not zeroed", entry)
        }
        cursor = offset;
        let buf = match size {
            Some(s) => reader.get(s * count)?,
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
                reader.get(len).expect("length is in bounds; qed")
            }
        };
        cursor += buf.len();
        cb(ty, entry, buf)?
    }
    fail_if!(reader.len() != 0, "{} bytes of trailing junk", reader.len());
    Ok(Header { index, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DigestCtx;
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
    #[test]
    fn parses_lua_rpm() {
        const S: &[u8] = include_bytes!("../../lua-5.4.2-1.fc33.x86_64.rpm");
        let mut r = &S[96..];
        let SignatureHeader {
            header: _,
            header_signature,
            header_payload_signature,
        } = load_signature(&mut r).unwrap();
        assert!(header_signature.is_some());
        assert!(header_payload_signature.is_some());
        let ImmutableHeader {
            header: _,
            payload_digest,
            payload_digest_algorithm,
        } = load_immutable(&mut r).unwrap();
        let payload_digest = payload_digest.unwrap();
        assert_eq!(payload_digest.len(), 65);
        assert_eq!(payload_digest_algorithm.unwrap(), 8);
        let mut digest_ctx = DigestCtx::init(8).unwrap();
        digest_ctx.update(r);
        assert_eq!(digest_ctx.finalize(true), payload_digest);
    }
}
