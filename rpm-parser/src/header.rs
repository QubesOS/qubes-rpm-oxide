//! Functions for parsing RPM headers
//!
//! RPM headers use an undocumented binary format.

#![deny(warnings)]
mod common;
mod immutable;
use super::ffi::{Signature, TagType};
use super::TagData;
use common::load_header;
pub use common::{Header, RPM_HDRMAGIC};
pub use immutable::{load_immutable, ImmutableHeader};
use openpgp_parser::buffer::Reader;
use std::io::{Read, Result};

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

/// A parsed RPM signature header
#[non_exhaustive]
pub struct SignatureHeader {
    /// The header
    pub header: Header,
    /// The header signature, if any
    pub header_signature: Option<(Signature, Vec<u8>)>,
    /// The header+payload signature, if any
    pub header_payload_signature: Option<(Signature, Vec<u8>)>,
}

/// Check that a `Reader` is a properly formatted hex string.  Assert that
/// it is NUL-terminated.
fn check_hex(untrusted_body: &[u8]) -> Result<()> {
    fail_if!(untrusted_body.len() & 1 != 0, "hex length not even");
    for &i in untrusted_body {
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
                check_hex(&body.as_untrusted_slice()[..body.len() - 1])
            }
            Flags::HeaderSig | Flags::HeaderPayloadSig => {
                let sig = match Signature::parse(body.clone(), 0) {
                    Ok(e) => e,
                    Err(e) => bad_data!("bad OpenPGP signature: {:?}", e),
                };
                match std::mem::replace(
                    if flags == Flags::HeaderSig {
                        &mut header_signature
                    } else {
                        &mut header_payload_signature
                    },
                    Some((sig, body.as_untrusted_slice().to_owned())),
                ) {
                    Some(_) => bad_data!("more than one signature of the same type"),
                    None => Ok(()),
                }
            }
        }
    };
    let header = load_header(r, 62, &mut cb)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DigestCtx;
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
            name,
            version,
            release,
            epoch,
            os,
            arch,
        } = load_immutable(&mut r).unwrap();
        let payload_digest = payload_digest.unwrap();
        assert_eq!(payload_digest.len(), 65);
        assert_eq!(payload_digest_algorithm.unwrap(), 8);
        assert_eq!(&*name, "lua");
        assert_eq!(&*version, "5.4.2");
        assert_eq!(&*release, "1.fc33");
        assert_eq!(epoch, None);
        assert_eq!(&*os, "linux");
        assert_eq!(&*arch, "x86_64");
        let mut digest_ctx = DigestCtx::init(8).unwrap();
        digest_ctx.update(r);
        assert_eq!(digest_ctx.finalize(true), payload_digest);
    }
}
