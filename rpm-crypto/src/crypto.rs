//! RPM cryptographic operations
//!
//! These operations use RPM’s own cryptography API, which is in turn provided
//! by either OpenSSL or libgcrypt depending on build configuration.

enum Expected {
    // Expected digest
    Hash(Vec<u8>),
    // Signature
    Signature(crate::Signature),
}

/// Something that can be cryptographically verified.
pub struct Item {
    ctx: DigestCtx,
    expected: Expected,
}

