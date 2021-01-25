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
//!
//! # Security
//!
//! `openpgp-parser` is part of [Qubes OS](https://www.qubes-os.org), where it
//! is used to validate RPM packages before verifying their signatures.  Please
//! report security vulnerabilities to <security@qubes-os.org>.
//!
//! `openpgp-parser` was created because its author, Demi M. Obenour, had found
//! several cases of memory unsafety in librpm.  While she was not able to find
//! an exploit, she wanted to ensure that QubesOS was protected in case one was
//! found.  This is especially important because QubesOS’s dom0 uses an old
//! version of RPM, which will not receive security patches.
//!
//! The following are considered security vulnerabilities:
//!
//! - Panics
//! - Accepting an ill-formed RPM.  This could be used to bypass validation and
//!   allow vulnerabilities in librpm to be exploited.
//! - Memory unsafety.  Since this crate contains no unsafe code, this would
//!   require a bug in the Rust compiler or standard library.
//! - Producing an RPM that is misparsed by the RPM C library.
//! - Accepting an RPM with an ill-formed GPG signature

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
