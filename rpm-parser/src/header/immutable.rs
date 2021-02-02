//! Functions for parsing RPM immutable headers

use super::{check_hex, load_header, Header};
use crate::ffi::{rpm_hash_len, tag_type, TagType};
use crate::TagData;
use openpgp_parser::buffer::Reader;
use std::convert::TryInto;
use std::io::{Error, ErrorKind, Read, Result};

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
    pub(super) payload_digest: Option<Vec<u8>>,
    pub(super) payload_digest_algorithm: Option<u8>,
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
                if rpm_hash_len(alg) != hash_len.into() {
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
                check_hex(&body.as_untrusted_slice()[..body.len() - 1])?;
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
                let epoch_ = body.be_u32_offset(0).expect("this is a i32 tag; qed") as i32;
                fail_if!(epoch_ < 0, "negative epoch {} not allowed", epoch_);
                epoch = Some(epoch_ as u32)
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
    let header = load_header(r, 63, &mut cb)?;
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
