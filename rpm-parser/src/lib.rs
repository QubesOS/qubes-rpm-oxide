//! A library for parsing and serializing RPM packages.  It does not rely on the
//! RPM C library for parsing.
//!
//! All interfaces of `rpm_syntax` are safe for use on untrusted packages.
//!
//! This library does not support building or installing RPM packages.  These
//! features can be found in the `rpm` crate, which uses the system RPM library.

#![deny(warnings)]
use std;
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

mod ffi;
pub mod header;
