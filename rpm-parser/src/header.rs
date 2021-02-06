//! Functions for parsing RPM headers
//!
//! RPM headers use an undocumented binary format.

#![deny(warnings)]
mod common;
mod immutable;
mod signature;
use common::load_header;
pub use common::{parse_header_magic, Header, RPM_HDRMAGIC};
pub use immutable::{load_immutable, ImmutableHeader};
pub use signature::{load_signature, SignatureHeader};
use std::io::Result;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DigestCtx;
    use openpgp_parser::AllowWeakHashes;
    #[test]
    fn parses_lua_rpm() {
        const S: &[u8] = include_bytes!("../../lua-5.4.2-1.fc33.x86_64.rpm");
        let mut r = &S[96..];
        let SignatureHeader {
            header: _,
            header_signature,
            header_payload_signature,
        } = load_signature(&mut r, AllowWeakHashes::No).unwrap();
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
            source,
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
        assert!(!source);
        let mut digest_ctx = DigestCtx::init(8, AllowWeakHashes::No).unwrap();
        digest_ctx.update(r);
        assert_eq!(digest_ctx.finalize(true), payload_digest);
    }
}
