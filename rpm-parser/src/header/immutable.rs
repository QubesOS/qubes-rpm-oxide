//! Functions for parsing RPM immutable headers

use super::super::ffi::{tag_class, tag_type, TagType};
use super::super::{RPMLead, TagData};
use super::{check_hex, load_header, u32_be_bytes, Header};
use openpgp_parser;
use openpgp_parser::AllowWeakHashes;
use rpm_crypto::{rpm_hash_len, DigestCtx, InitToken};
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
    /// Is this a source package?
    pub source: bool,
    pub(super) payload_digest: Option<Vec<u8>>,
    pub(super) payload_digest_algorithm: Option<u8>,
    token: InitToken,
}
include!("../tables.rs");

impl ImmutableHeader {
    /// Gets a digest context for the package payload, along with the hex digest
    /// to verify it against.
    pub fn payload_digest(&self) -> Result<(DigestCtx, Vec<u8>)> {
        let alg = match self.payload_digest_algorithm {
            None => bad_data!("No payload digest algorithm"),
            Some(e) => e,
        };
        // We already checked the digest algorithm
        let ctx = DigestCtx::init(alg, AllowWeakHashes::Yes, self.token)
            .expect("algorithm already validated");
        let digest = self
            .payload_digest
            .as_ref()
            .expect("payload digest algorithms with no digests rejected earlier")
            .clone();
        Ok((ctx, digest))
    }

    /// Retrieves the package lead
    pub fn lead(&self) -> [u8; 96] {
        let (osnum, archnum) = (
            os_to_osnum(self.os.as_bytes()).unwrap_or(0),
            arch_to_archnum(self.arch.as_bytes()).unwrap_or(0),
        );
        let &Self {
            ref name,
            ref version,
            ref release,
            source,
            epoch,
            ..
        } = self;
        let full_name = match epoch {
            Some(epoch) => format!("{}-{}:{}-{}", name, epoch, version, release),
            None => format!("{}-{}-{}", name, version, release),
        };
        RPMLead::new(source, archnum, osnum, full_name.as_bytes()).as_slice()
    }
}

pub fn load_immutable(r: &mut Read, token: InitToken) -> Result<ImmutableHeader> {
    let mut payload_digest_algorithm = None;
    let mut payload_digest: Option<Vec<u8>> = None;
    let mut name: Option<String> = None;
    let mut version = None;
    let mut release = None;
    let mut epoch = None;
    let mut os = None;
    let mut source = true;
    let mut arch = None;
    let header = {
        let mut cb = |ty: TagType, tag_data: &TagData, body: &[u8]| -> Result<()> {
            let tag = tag_data.tag();
            fail_if!(tag < 1000 && tag != 100, "signature in immutable header");
            fail_if!(tag > 0x7FFF, "type too large");
            match tag_type(tag) {
                Some((t, _is_array)) if t == ty || (tag_class(t) == 2 && tag_class(ty) == 2) => {}
                None => {}
                Some((t, _)) => {
                    bad_data!(
                        "wrong type in immutable header: for tag {}, expected {:?} but got {:?}",
                        tag,
                        t,
                        ty
                    )
                }
            }
            match tag {
                5093 => {
                    // payload digest algorithm
                    assert_eq!(ty, TagType::Int32);
                    if body.len() != 4 {
                        // RPM might make this an array in the future
                        bad_data!("wrong length")
                    }
                    let alg = u32_be_bytes(body) as i32;
                    // We never allow weak payload digests, as there is no point
                    // to using them and we are not aware of anyone ever
                    // generating them.
                    let hash_len =
                        openpgp_parser::signature::check_hash_algorithm(alg, AllowWeakHashes::No)
                            .map_err(|e| {
                            Error::new(
                                ErrorKind::InvalidData,
                                format!("bad algorithm {}: {:?}", alg, e),
                            )
                        })?;
                    if rpm_hash_len(alg) != hash_len as usize {
                        bad_data!("Unsupported hash algorithm {}", alg)
                    }
                    match payload_digest {
                        None => bad_data!("no payload digest"),
                        Some(ref e) if e.len() == (2 * hash_len + 1) as usize => {}
                        Some(_) => bad_data!("wrong payload digest length"),
                    }
                    payload_digest_algorithm =
                        Some(alg.try_into().expect("invalid algorithm rejected above"))
                }
                5092 | 5097 => {
                    // payload digest
                    fail_if!(tag_data.count() != 1, "more than one payload digest?");
                    check_hex(body)?;
                    if tag == 5092 {
                        assert!(payload_digest.is_none(), "duplicate tags rejected earlier");
                        payload_digest = Some(body.to_owned())
                    }
                }
                // package name
                1000 => {
                    name = Some(
                        String::from_utf8(body[..body.len() - 1].to_vec())
                            .expect("String header checked to be valid UTF-8"),
                    )
                }
                // package version
                1001 => {
                    version = Some(
                        String::from_utf8(body[..body.len() - 1].to_vec())
                            .expect("String header checked to be valid UTF-8"),
                    )
                }
                // package release
                1002 => {
                    release = Some(
                        String::from_utf8(body[..body.len() - 1].to_vec())
                            .expect("String header checked to be valid UTF-8"),
                    )
                }
                // package epoch
                1003 => {
                    fail_if!(body.len() != 4, "wrong length");
                    let epoch_ = u32_be_bytes(body) as i32;
                    fail_if!(epoch_ < 0, "negative epoch {} not allowed", epoch_);
                    epoch = Some(epoch_ as u32)
                }
                // package os
                1021 => {
                    os = Some(
                        String::from_utf8(body[..body.len() - 1].to_vec())
                            .expect("String header checked to be valid UTF-8"),
                    )
                }
                // package architecture
                1022 => {
                    arch = Some(
                        String::from_utf8(body[..body.len() - 1].to_vec())
                            .expect("String header checked to be valid UTF-8"),
                    )
                }
                // source RPM package built from
                1044 => source = false,
                _ => {}
            }
            Ok(())
        };
        load_header(r, 63, &mut cb, false)?
    };
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
            source,
            token,
        }),
        _ => bad_data!("Missing name, OS, arch, version, or release"),
    }
}
