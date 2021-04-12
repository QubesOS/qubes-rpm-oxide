//! A library for parsing and serializing RPM packages.  It does not rely on the
//! RPM C library for parsing.
//!
//! All interfaces of `rpm_syntax` are safe for use on untrusted packages.
//!
//! This library does not support building or installing RPM packages.  These
//! features can be found in the `rpm` crate, which uses the system RPM library.

// #![deny(warnings)]
#![feature(i128_type)]
#![feature(try_from)]
#![feature(const_fn)]
macro_rules! size_of {
    ($t:ty) => {
        $crate::std::mem::size_of::<$t>()
    };
}

macro_rules! align_of {
    ($t:ty) => {
        $crate::std::mem::align_of::<$t>()
    };
}

macro_rules! bad_data {
    ($i:expr) => {
        return Err($crate::std::io::Error::new($crate::std::io::ErrorKind::InvalidData, $i))
    };
    ($($i:expr),*) => {
        return Err($crate::std::io::Error::new($crate::std::io::ErrorKind::InvalidData, format!($($i),*)))
    };
    ($($i:expr),*,) => {
        bad_data!($($i),*)
    };
}

macro_rules! fail_if {
    ($c:expr, $($i:expr),*,) => {
        if $c {
            bad_data!($($i),*)
        }
    };
    ($c:expr, $($i:expr),*) => {
        if $c {
            bad_data!($($i),*)
        }
    };
}

extern crate openpgp_parser;
extern crate rpm_crypto;
mod ffi;
mod header;
mod lead;
mod package;
mod tagdata;
mod verify;
pub use ffi::TagType;
pub use header::Header as RPMHeader;
pub use header::{load_immutable, load_signature, parse_header_magic, RPM_HDRMAGIC};
pub use header::{ImmutableHeader as MainHeader, SignatureHeader};
pub use lead::{read_lead, RPMLead};
pub use package::RPMPackage;
pub use tagdata::TagData;
pub use verify::{verify_package, VerifyResult};
