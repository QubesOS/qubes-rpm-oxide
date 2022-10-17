//! A library for parsing and serializing RPM packages.  It does not rely on the
//! RPM C library for parsing.
//!
//! All interfaces of `rpm_syntax` are safe for use on untrusted packages.
//!
//! This library does not support building or installing RPM packages.  These
//! features can be found in the `rpm` crate, which uses the system RPM library.

// #![deny(warnings)]
#![cfg_attr(bare_trait_obj_deprecated, allow(bare_trait_objects))]
#![cfg_attr(
    ellipsis_inclusive_range_deprecated,
    allow(ellipsis_inclusive_range_patterns)
)]
#![cfg_attr(const_fn_unstable, feature(const_fn))]
#![cfg_attr(try_from_unstable, feature(try_from))]

#[cfg(any(
    not(any(const_fn_stable, const_fn_unstable)),
    not(any(bare_trait_obj_deprecated, bare_trait_obj_allowed)),
    not(any(ellipsis_inclusive_range_deprecated, ellipsis_inclusive_range_allowed)),
    not(any(try_from_stable, try_from_unstable))
))]
compile_error!("build script bug");

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
pub use crate::ffi::TagType;
pub use crate::header::Header as RPMHeader;
pub use crate::header::{load_immutable, load_signature, parse_header_magic, RPM_HDRMAGIC};
pub use crate::header::{read_header_magic, ImmutableHeader as MainHeader, SignatureHeader};
pub use crate::lead::{read_lead, RPMLead};
pub use crate::package::RPMPackage;
pub use crate::tagdata::TagData;
pub use crate::verify::{verify_package, VerifyResult};
