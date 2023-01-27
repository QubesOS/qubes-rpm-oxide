use super::super::ffi::TagType;
use super::super::TagData;
use super::super::{openpgp_parser, rpm_crypto};
use super::{check_hex, load_header, Header};
use openpgp_parser::AllowWeakHashes;
use rpm_crypto::{DigestCtx, Signature};
use std;
use std::io::{Read, Result};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Flags {
    None,
    HeaderSig,
    HeaderPayloadSig,
    HeaderDigest,
    HeaderPayloadDigest,
    Zeroed,
}

const RPMSIGTAG_SHA1HEADER: u32 = 256 + 13;
const RPMSIGTAG_SHA256HEADER: u32 = 256 + 17;

macro_rules! stuff {
    ($($(#[doc = $e:expr])+($a:expr,$b:expr,$c:expr,$d:expr)),*) => {
        [
            $(($a, $b, $c, $d, concat!($($e),+))),*
        ]
    }
}

static RPM_SIG_TAGS: &'static [(u32, TagType, Option<usize>, Flags, &'static str)] = &stuff![
    /// Header signature
    (256 + 11, TagType::Bin, None, Flags::HeaderSig),
    /// Header signature
    (256 + 12, TagType::Bin, None, Flags::HeaderSig),
    /// Header SHA1 hash
    (
        RPMSIGTAG_SHA1HEADER,
        TagType::String,
        Some(41),
        Flags::HeaderDigest
    ),
    /// 64 bit Header+Payload size
    (256 + 14, TagType::Int64, Some(8), Flags::None),
    /// 64 bit uncompressed payload size
    (256 + 15, TagType::Int64, Some(8), Flags::None),
    /// Hex SHA256 hash of the header
    (
        RPMSIGTAG_SHA256HEADER,
        TagType::String,
        Some(65),
        Flags::HeaderDigest
    ),
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
    (1008, TagType::Bin, None, Flags::Zeroed)
];

/// A parsed RPM signature header
pub struct SignatureHeader {
    /// The header
    pub header: Header,
    /// The header signature, if any
    pub header_signature: Option<(Signature, Vec<u8>)>,
    /// The header+payload signature, if any
    pub header_payload_signature: Option<(Signature, Vec<u8>)>,
    /// The header+payload MD5 digest, if any
    pub header_payload_weak_digest: Option<(DigestCtx, Vec<u8>)>,
    /// The SHA1 hash of the main header, if provided
    pub header_sha1_hash: Option<(DigestCtx, Vec<u8>)>,
    /// The SHA256 hash of the main header, if provided
    pub header_sha256_hash: Option<(DigestCtx, Vec<u8>)>,
}

pub fn load_signature(
    r: &mut dyn Read,
    allow_weak_hashes: AllowWeakHashes,
    token: rpm_crypto::InitToken,
) -> Result<SignatureHeader> {
    let mut header_signature = None;
    let mut header_payload_signature = None;
    let mut header_payload_weak_digest = None;
    let mut header_sha1_hash = None;
    let mut header_sha256_hash = None;
    if cfg!(test) {
        let mut s = RPM_SIG_TAGS[0].0;
        for i in &RPM_SIG_TAGS[1..] {
            assert!(i.0 > s, "{:?} not greater than {:?}", i.0, s);
            s = i.0;
        }
    }
    let header = {
        let mut cb = |ty: TagType, tag_data: &TagData, body: &[u8]| {
            let tag = tag_data.tag();
            let (_, expected_ty, size, flags, _) =
                match RPM_SIG_TAGS.binary_search_by_key(&tag, |x| x.0) {
                    Ok(e) => RPM_SIG_TAGS[e],
                    Err(_) => return Ok(()),
                };
            if ty != expected_ty {
                bad_data!("bogus tag type {:?} for tag {}", ty, tag)
            } else if let Some(size) = size {
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
                Flags::HeaderPayloadDigest => {
                    // In FIPS mode this will fail, but that is okay
                    header_payload_weak_digest = DigestCtx::init(1, AllowWeakHashes::Yes, token)
                        .ok()
                        .map(|s| (s, body.to_owned()));
                    Ok(())
                }
                Flags::None => Ok(()),
                Flags::Zeroed => Ok(for &i in body {
                    fail_if!(i != 0, "padding not zeroed")
                }),
                Flags::HeaderDigest => {
                    // our lengths include the terminating NUL
                    check_hex(body)?;
                    let (ref_, id) = match tag {
                        RPMSIGTAG_SHA1HEADER => (&mut header_sha1_hash, 2),
                        RPMSIGTAG_SHA256HEADER => (&mut header_sha256_hash, 8),
                        _ => unreachable!("no other tags with this flag"),
                    };
                    *ref_ = DigestCtx::init(id, AllowWeakHashes::Yes, token)
                        .ok()
                        .map(|s| (s, body.to_owned()));
                    Ok(())
                }
                Flags::HeaderSig | Flags::HeaderPayloadSig => {
                    use std::time::SystemTime;
                    use std::time::UNIX_EPOCH;
                    let time = match SystemTime::now().duration_since(UNIX_EPOCH) {
                        Ok(d) => {
                            let secs = d.as_secs();
                            if secs > 0 && secs < u32::max_value().into() {
                                secs as u32
                            } else {
                                bad_data!("Bad secs since the epoch {:?} (delta is {}) - check your system clock", d, secs)
                            }
                        }
                        Err(e) => bad_data!("Your system clock is really wrong: {}", e),
                    };
                    let sig = match Signature::parse(body, time, allow_weak_hashes, token) {
                        Ok(e) => e,
                        Err(e) => bad_data!("bad OpenPGP signature: {:?}", e),
                    };
                    let sig_packet =
                        openpgp_parser::packet::next(&mut openpgp_parser::Reader::new(body))
                            .expect("already validated above; qed")
                            .expect("already validated above; qed")
                            .serialize();

                    match std::mem::replace(
                        if flags == Flags::HeaderSig {
                            &mut header_signature
                        } else {
                            &mut header_payload_signature
                        },
                        Some((sig, sig_packet)),
                    ) {
                        Some(_) => bad_data!("more than one signature of the same type"),
                        None => Ok(()),
                    }
                }
            }
        };
        load_header(r, 62, &mut cb, true)?
    };
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
        header_payload_weak_digest,
        header_sha1_hash,
        header_sha256_hash,
    })
}
