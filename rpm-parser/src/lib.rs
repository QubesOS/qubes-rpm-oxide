//! A library for parsing and serializing RPM packages.  It does not rely on the
//! RPM C library for parsing.
//!
//! All interfaces of `rpm_syntax` are safe for use on untrusted packages.
//!
//! This library does not support building or installing RPM packages.  These
//! features can be found in the `rpm` crate, which uses the system RPM library.

// #![deny(warnings)]
macro_rules! size_of {
    ($t:ty) => {
        ::core::mem::size_of::<$t>()
    };
}

macro_rules! align_of {
    ($t:ty) => {
        ::core::mem::align_of::<$t>()
    };
}

macro_rules! bad_data {
    ($i:expr) => {
        return Err(::std::io::Error::new(::std::io::ErrorKind::InvalidData, $i))
    };
    ($($i:expr),*) => {
        return Err(::std::io::Error::new(::std::io::ErrorKind::InvalidData, format!($($i),*)))
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

use openpgp_parser;
use rpm_crypto;
mod ffi;
mod header;
mod lead;
mod package;
mod tagdata;
mod verify;
pub use crate::ffi::TagType;
pub use crate::header::Header as RPMHeader;
pub use crate::header::{load_immutable, load_signature, parse_header_magic, RPM_HDRMAGIC};
pub use crate::header::{read_header_magic, ImmutableHeader as MainHeader, SignatureHeader};
pub use crate::lead::{read_lead, RPMLead};
pub use crate::package::RPMPackage;
pub use crate::tagdata::TagData;
pub use crate::verify::{verify_package, VerifyResult};
