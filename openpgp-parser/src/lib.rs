//! A library for parsing and serializing RPM packages.  It does not rely on the
//! RPM C library, and contains no unsafe code.
//!
//! All interfaces of `rpm_syntax` are safe for use on untrusted packages.
//! Since `rpm_syntax` does not use the RPM C library, it is not limited to
//! \*nix-like systems.
//!
//! This library does not support building or installing RPM packages.  These
//! features can be found in the `rpm` crate, which uses the system RPM library.
//!
//! # Features
//!
//! `rpm_syntax` has several Cargo features that can be turned on.  All of these
//! are off by default.
//!
//! - `serialize`: Enables serializing RPM packages, as well as parsing them.
//!   This currently imples `alloc`.
//! - `alloc`: Features that allocate memory.  This is currently an alias for
//!   `serialize`, but this may change in the future.
//! - `std`: Features that require the standard library, such as I/O.  This
//!   implies `alloc`.

#![forbid(missing_docs, unsafe_code)]
#![deny(warnings)]
pub mod openpgp;
pub mod buffer;
//mod header;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
