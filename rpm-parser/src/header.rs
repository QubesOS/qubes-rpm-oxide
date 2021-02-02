//! Functions for parsing RPM headers
//!
//! RPM headers use an undocumented binary format.

#![deny(warnings)]
mod common;
use super::ffi::{tag_type, Signature, TagType};
use super::TagData;
use common::{load_header, HeaderType};
pub use common::{Header, RPM_HDRMAGIC};
use openpgp_parser::buffer::Reader;
use std::convert::TryInto;
use std::io::{Error, ErrorKind, Read, Result};

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

/// A parsed RPM immutable header
pub struct ImmutableHeader {
    /// The header
    pub header: Header,
    /// The package name
    pub name: String,
    /// The package version
    pub version: String,
    /// The package release
    pub release: String,
    /// The package epoch, if any
    pub epoch: Option<u32>,
    /// The package target operating system
    pub os: String,
    /// The package architecture
    pub arch: String,
    payload_digest: Option<Vec<u8>>,
    payload_digest_algorithm: Option<u8>,
}

impl ImmutableHeader {
    /// Gets a digest context for the package payload, along with the hex digest
    /// to verify it against.
    pub fn payload_digest(&self) -> Result<(crate::DigestCtx, Vec<u8>)> {
        let alg = match self.payload_digest_algorithm {
            None => bad_data!("No payload digest algorithm"),
            Some(e) => e,
        };
        let ctx = crate::DigestCtx::init(alg).expect("algorithm already validated");
        let digest = self
            .payload_digest
            .as_ref()
            .expect("payload digest algorithms with no digests rejected earlier")
            .clone();
        Ok((ctx, digest))
    }
}

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
    let mut name: Option<String> = None;
    let mut version = None;
    let mut release = None;
    let mut epoch = None;
    let mut os = None;
    let mut arch = None;
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
        match tag {
            5093 => {
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
                payload_digest_algorithm =
                    Some(alg.try_into().expect("invalid algorithm rejected above"))
            }
            5092 | 5097 => {
                // payload digest
                fail_if!(tag_data.count() != 1, "more than one payload digest?");
                check_hex(body.clone())?;
                if tag == 5092 {
                    assert!(payload_digest.is_none(), "duplicate tags rejected earlier");
                    payload_digest = Some(body.as_untrusted_slice().to_owned())
                }
            }
            // package name
            1000 => {
                name = Some(
                    String::from_utf8(
                        body.as_untrusted_slice()[..body.as_untrusted_slice().len() - 1].to_vec(),
                    )
                    .expect("String header checked to be valid UTF-8"),
                )
            }
            // package version
            1001 => {
                version = Some(
                    String::from_utf8(
                        body.as_untrusted_slice()[..body.as_untrusted_slice().len() - 1].to_vec(),
                    )
                    .expect("String header checked to be valid UTF-8"),
                )
            }
            // package release
            1002 => {
                release = Some(
                    String::from_utf8(
                        body.as_untrusted_slice()[..body.as_untrusted_slice().len() - 1].to_vec(),
                    )
                    .expect("String header checked to be valid UTF-8"),
                )
            }
            // package epoch
            1003 => {
                let epoch_ = body
                    .be_u32_offset(0)
                    .expect("we checked earlier that the count is correct");
                fail_if!(epoch_ > i32::MAX as u32, "Epoch {} too large", epoch_);
                epoch = Some(epoch_)
            }
            // package os
            1021 => {
                os = Some(
                    String::from_utf8(
                        body.as_untrusted_slice()[..body.as_untrusted_slice().len() - 1].to_vec(),
                    )
                    .expect("String header checked to be valid UTF-8"),
                )
            }
            // package architecture
            1022 => {
                arch = Some(
                    String::from_utf8(
                        body.as_untrusted_slice()[..body.as_untrusted_slice().len() - 1].to_vec(),
                    )
                    .expect("String header checked to be valid UTF-8"),
                )
            }
            _ => {}
        }
        Ok(())
    };
    let header = load_header(r, HeaderType::Immutable, &mut cb)?;
    match (name, os, arch, version, release) {
        (Some(name), Some(os), Some(arch), Some(version), Some(release)) => Ok(ImmutableHeader {
            header,
            payload_digest_algorithm,
            payload_digest,
            name,
            version,
            release,
            epoch,
            os,
            arch,
        }),
        _ => bad_data!("Missing name, OS, arch, version, or release"),
    }
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
