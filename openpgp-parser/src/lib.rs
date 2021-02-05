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

#![forbid(missing_docs, unsafe_code, deprecated)]
#![deny(warnings)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]
pub use buffer::{EOFError, Reader};
mod buffer;
pub mod packet;
pub mod signature;

/// Errors that can occur during parsing
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// First bit of the first byte of a packet is zero
    PacketFirstBitZero,
    /// Length field is too long
    TooLong,
    /// Packet is truncated
    PrematureEOF,
    /// Indefinite-length old format packet detected.  These are not supported.
    IndefiniteLength,
    /// Partial-length new format packet detected.  These are not supported.
    PartialLength,
    /// Bad tag
    BadTag,
    /// Trailing junk
    TrailingJunk,
    /// Bogus MPI
    BadMPI,
    /// Ill-formed signature
    IllFormedSignature,
    /// Unsupported hash algorithm
    UnsupportedHashAlgorithm(i32),
    /// Unsupported public-key algorithm
    UnsupportedPkeyAlgorithm(u8),
    /// Insecure algorithm
    InsecureAlgorithm(i32),
    /// Invalid public-key algorithm (such as an encryption algorithm uesd for signatures)
    InvalidPkeyAlgorithm(u8),
    /// Signature not valid yet
    SignatureNotValidYet,
    /// Signature expired
    SignatureExpired,
    /// No creation time
    NoCreationTime,
    /// Unsupported critical subpacket
    UnsupportedCriticalSubpacket,
}

impl From<core::num::TryFromIntError> for Error {
    fn from(_e: core::num::TryFromIntError) -> Error {
        Error::TooLong
    }
}
