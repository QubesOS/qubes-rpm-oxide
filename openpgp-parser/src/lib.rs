//! A library for parsing OpenPGP packets
//!
//! `openpgp-parser` is a Rust library for validating OpenPGP packets.  It has
//! no cryptography of its own, and is instead designed to validate packets that
//! will be passed to a different OpenPGP implementation.

#![cfg_attr(
    ellipsis_inclusive_range_deprecated,
    allow(ellipsis_inclusive_range_patterns)
)]
#![forbid(missing_docs, unsafe_code, deprecated)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(any(not(any(ellipsis_inclusive_range_deprecated, ellipsis_inclusive_range_allowed)),))]
compile_error!("build script bug");

pub use buffer::{EOFError, Reader};
mod buffer;
pub mod packet;
pub mod signature;

#[cfg(target_pointer_width = "16")]
compile_error!("Sorry, 16-bit targets not supported");

pub use signature::AllowWeakHashes;

/// Errors that can occur during parsing
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// First bit of the first byte of a packet is zero
    PacketFirstBitZero,
    /// Length field is too long
    TooLong,
    /// Packet is truncated
    PrematureEOF,
    /// Unsupported signature version
    UnsupportedSignatureVersion,
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
    /// Unknown public-key algorithm
    UnknownPkeyAlgorithm(u8),
    /// Unsupported public-key algorithm
    UnsupportedPkeyAlgorithm(u8),
    /// Insecure algorithm
    InsecureAlgorithm(i32),
    /// Invalid public-key algorithm (such as an encryption algorithm uesd for signatures)
    InvalidPkeyAlgorithm(u8),
    /// Public-key algorithm requires v4 signature
    PkeyAlgorithmRequiresV4Sig(u8),
    /// Signature not valid yet
    SignatureNotValidYet,
    /// Signature expired
    SignatureExpired,
    /// No creation time
    NoCreationTime,
    /// Unsupported critical subpacket
    UnsupportedCriticalSubpacket(u8),
    /// Wrong signature type
    WrongSignatureType {
        /// The expected signature type
        expected_type: signature::SignatureType,
        /// The actual signature type
        actual_type: u8,
    },
}
