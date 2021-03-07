//! FFI bindings to RPM’s cryptographic API
//!
//! `librpmio`, which is part of RPM, exposes some cryptographic routines for
//! use by third party applications.  This crate provides Rust bindings to that
//! code.

#![forbid(improper_ctypes)]
#![deny(warnings)]

use openpgp_parser::{AllowWeakHashes, Error};

mod digests;
mod signatures;
pub mod transaction;
pub use digests::{rpm_hash_len, DigestCtx};
pub use signatures::Signature as RawSignature;

/// An OpenPGP signature
pub struct Signature {
    sig: RawSignature,
    ctx: DigestCtx,
}

pub use init::{init, InitToken};

mod init {
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct InitToken(());
    pub fn init() -> InitToken {
        use std::sync::Once;
        static RPM_CRYPTO_INIT_ONCE: Once = Once::new();
        use std::os::raw::{c_char, c_int};
        use std::ptr;
        #[link(name = "rpm")]
        extern "C" {
            fn rpmReadConfigFiles(file: *const c_char, target: *const c_char) -> c_int;
        }
        RPM_CRYPTO_INIT_ONCE
            .call_once(|| assert_eq!(unsafe { rpmReadConfigFiles(ptr::null(), ptr::null()) }, 0));
        InitToken(())
    }
}

impl Signature {
    /// Parse an OpenPGP signature.  The signature is validated before being
    /// passed to RPM.  If the time is not zero, the signature is checked to not
    /// be from the future and to not have expired.
    pub fn parse(
        untrusted_buffer: &[u8],
        time: u32,
        allow_sha1_sha224: AllowWeakHashes,
        token: InitToken,
    ) -> Result<Self, Error> {
        let sig = RawSignature::parse(untrusted_buffer, time, allow_sha1_sha224, token)?;
        let ctx = DigestCtx::init(sig.hash_algorithm(), allow_sha1_sha224, token)
            .expect("Digest algorithm already validated");
        Ok(Self { sig, ctx })
    }

    /// Update the sigatures’s internal digest context with data from `buf`.
    pub fn update(&mut self, buf: &[u8]) {
        self.ctx.update(buf)
    }

    pub fn public_key_algorithm(&self) -> u8 {
        self.sig.public_key_algorithm()
    }
}
