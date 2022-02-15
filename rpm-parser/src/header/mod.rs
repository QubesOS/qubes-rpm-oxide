//! Functions for parsing RPM headers
//!
//! RPM headers use an undocumented binary format.

// #![deny(warnings)]
mod common;
mod immutable;
mod signature;
use self::common::load_header;
pub use self::common::{parse_header_magic, read_header_magic, Header, RPM_HDRMAGIC};
pub use self::immutable::{load_immutable, ImmutableHeader};
pub use self::signature::{load_signature, SignatureHeader};
use std::io::Result;

fn u32_be_bytes(buf: &[u8]) -> u32 {
    u32::from(buf[0]) << 24 | u32::from(buf[1]) << 16 | u32::from(buf[2]) << 8 | u32::from(buf[3])
}

/// Check that a `Reader` is a properly formatted, NUL-terminated hex string.
fn check_hex(untrusted_body: &[u8]) -> Result<()> {
    let len = untrusted_body.len();
    fail_if!(len & 1 == 0, "hex length not even");
    let len = len - 1;
    fail_if!(untrusted_body[len] != b'\0', "missing NUL terminator");
    for &i in &untrusted_body[..len] {
        match i {
            b'a'...b'f' | b'0'...b'9' => (),
            _ => bad_data!("bad hex"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp_parser::AllowWeakHashes;
    use rpm_crypto;
    #[test]
    fn parses_lua_rpm() {
        let token = rpm_crypto::init(None);
        const S: &[u8] = include_bytes!("../../../data/lua-5.4.2-1.fc33.x86_64.rpm");
        let mut r = &S[96..];
        let SignatureHeader {
            header: _,
            header_signature,
            header_payload_signature,
            header_payload_weak_digest,
            header_sha1_hash,
            header_sha256_hash,
        } = load_signature(&mut r, AllowWeakHashes::No, token).unwrap();
        assert!(header_signature.is_some());
        assert!(header_payload_signature.is_some());
        assert!(header_payload_weak_digest.is_some());
        assert!(header_sha1_hash.is_some());
        assert!(header_sha256_hash.is_some());
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
            source,
            ..
        } = load_immutable(&mut r, token).unwrap();
        let payload_digest = payload_digest.unwrap();
        assert_eq!(payload_digest.len(), 65);
        assert_eq!(payload_digest_algorithm.unwrap(), 8);
        assert_eq!(&*name, "lua");
        assert_eq!(&*version, "5.4.2");
        assert_eq!(&*release, "1.fc33");
        assert_eq!(epoch, None);
        assert_eq!(&*os, "linux");
        assert_eq!(&*arch, "x86_64");
        assert!(!source);
        let mut digest_ctx = rpm_crypto::DigestCtx::init(8, AllowWeakHashes::No, token).unwrap();
        digest_ctx.update(r);
        assert_eq!(digest_ctx.finalize(true), payload_digest);
    }
}
