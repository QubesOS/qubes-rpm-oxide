//! FFI code
#![forbid(improper_ctypes)]
use openpgp_parser::Error;

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
    pub fn parse(untrusted_buffer: &[u8], time: u32, _: InitToken) -> Result<Self, Error> {
        let sig = RawSignature::parse(untrusted_buffer, time)?;
        let ctx =
            DigestCtx::init(sig.hash_algorithm()).expect("Digest algorithm already validated");
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

mod digests;
mod signatures;
mod transaction;
use signatures::Signature as RawSignature;

pub use digests::DigestCtx;
pub use transaction::{RpmKeyring, RpmTransactionSet};

#[link(name = "rpm")]
extern "C" {
    fn rpmTagGetType(tag: std::os::raw::c_int) -> std::os::raw::c_int;
    fn rpmTagTypeGetClass(tag: std::os::raw::c_int) -> std::os::raw::c_int;
}

#[link(name = "rpmio")]
extern "C" {
    fn rpmDigestLength(tag: std::os::raw::c_int) -> usize;
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TagType {
    Char = 1,
    Int8 = 2,
    Int16 = 3,
    Int32 = 4,
    Int64 = 5,
    String = 6,
    Bin = 7,
    StringArray = 8,
    I18NString = 9,
}

pub fn rpm_hash_len(alg: i32) -> usize {
    unsafe { rpmDigestLength(alg) }
}

pub fn tag_type(tag: u32) -> Option<(TagType, bool)> {
    if tag > 0x7FFF {
        return None;
    }
    let ty = unsafe { rpmTagGetType(tag as _) };
    let is_array = match ty as u32 & 0xffff_0000 {
        0x10000 => false,
        0x20000 => true,
        // This should probably be a panic, but RPM does define
        // RPM_MAPPING_RETURN_TYPE, so just fail.
        _ => {
            if cfg!(test) && ty != 0 {
                panic!("bad return from RPM")
            } else {
                return None;
            }
        }
    };
    Some((
        match ty & 0xffff {
            0 => return None,
            1 => TagType::Char,
            2 => TagType::Int8,
            3 => TagType::Int16,
            4 => TagType::Int32,
            5 => TagType::Int64,
            6 => TagType::String,
            7 => TagType::Bin,
            8 => TagType::StringArray,
            9 => TagType::I18NString,
            _ => unreachable!("invalid return from rpmTagGetTagType()"),
        },
        is_array,
    ))
}

pub fn tag_class(ty: TagType) -> std::os::raw::c_int {
    unsafe { rpmTagTypeGetClass(ty as _) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_rpm_supports_hashes() {
        use openpgp_parser::signature::check_hash_algorithm;
        for &i in &[8, 9, 10] {
            assert_eq!(
                unsafe { rpmDigestLength(i) },
                check_hash_algorithm(i).unwrap().into()
            );
        }
    }
    #[test]
    fn check_rpm_crypto() {
        for &i in &[8, 9, 10] {
            let mut s = DigestCtx::init(i).unwrap();
            println!("Initialized RPM crypto context");
            s.update(b"this is a test!");
            println!("Finalizing");
            let hex = s.clone().finalize(true);
            let len = hex.len();
            assert!(len & 1 == 1);
            assert_eq!(hex[len - 1], 0);
            println!(
                "Hex version: {}",
                std::str::from_utf8(&hex[..len - 1]).unwrap()
            );
            println!("{:?}", s.finalize(false))
        }
    }
    #[test]
    fn check_rpm_return() {
        for i in 0..0x8000 {
            tag_type(i);
        }
    }
}
