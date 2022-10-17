//! OpenPGP signatures

use super::{packet, Error, Reader};
use crate::packet::get_varlen_bytes;

extern crate core;

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
/// Should weak hashes (less than 256 bits and vulnerable to collisions) be allowed?
pub enum AllowWeakHashes {
    /// Do not allow weak hashes
    No,
    /// Allow weak hashes
    Yes,
}

/// Signature types
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[repr(u8)]
pub enum SignatureType {
    /// Signature of a binary document
    Binary = 0,
    /// Signature of a text document with CRLF line endings
    Text = 1,
    /// Standalone
    Standalone = 2,
    /// Generic certification
    GenericCert = 0x10,
    /// Persona certification
    PersonaCert = 0x11,
    /// Casual certification
    CasualCert = 0x12,
    /// Positive certification
    PositiveCert = 0x13,
    /// Subkey binding
    SubkeyBinding = 0x18,
    /// Primary-key binding
    PrimaryKeyBinding = 0x19,
    /// Signature directly on a key
    KeySig = 0x1F,
    /// Primary key revocation
    PrimaryKeyRevocation = 0x20,
    /// Subkey revocation
    SubkeyRevocation = 0x28,
    /// Certification revocation
    CertificationRevocatin = 0x30,
    /// Timestamp
    Timestamp = 0x40,
}

/// Rivest-Shamir-Aldeman (RSA) cryptography
const OPENPGP_PUBLIC_KEY_RSA: u8 = 1;

/// Legacy encrypt-only RSA
const OPENPGP_PUBLIC_KEY_LEGACY_RSA_ENCRYPT_ONLY: u8 = 2;

/// Legacy sign-only RSA
const OPENPGP_PUBLIC_KEY_LEGACY_RSA_SIGN_ONLY: u8 = 3;

/// Encrypt-only ElGamal
const OPENPGP_PUBLIC_KEY_ELGAMAL_ENCRYPT_ONLY: u8 = 16;

/// Finite-field Digital Signature Algorithm (DSA)
const OPENPGP_PUBLIC_KEY_DSA: u8 = 17;

/// Elliptic-curve Diffe-Hellman
const OPENPGP_PUBLIC_KEY_ECDH: u8 = 18;

/// Elliptic-curve Digital Signature Algorithm
const OPENPGP_PUBLIC_KEY_ECDSA: u8 = 19;

/// ElGamal signing and encryption.  This is insecure as ElGamal signatures
/// have been broken.
const OPENPGP_PUBLIC_KEY_INSECURE_ELGAMAL_SIGN_ENCRYPT: u8 = 20;

/// Finite-field Diffe-Hellman
const OPENPGP_PUBLIC_KEY_DH: u8 = 21;

/// Edwards-curve Digital Signature Algorithm
const OPENPGP_PUBLIC_KEY_EDDSA: u8 = 22;

/// Read a multiprecision integer (MPI) from `reader`.  Value is returned as a
/// slice.
pub fn read_mpi<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    reader.read(|reader| {
        let bits = 7 + reader.be_u16()? as usize;
        if bits == 7 {
            // Empty MPI is invalid
            return Err(Error::BadMPI);
        }
        let mpi_buf = reader.get_bytes(bits >> 3)?;
        // don’t use ‘Reader::byte’, which mutates the reader
        if let Some(first_byte) = mpi_buf.get(0) {
            // check that there are no spurious leading zeros
            // this is not valid for encrypted MPIs, but we don’t deal with
            // them, as we only parse signatures
            if first_byte.leading_zeros() as usize + (bits & 7) != 7 {
                return Err(Error::BadMPI);
            }
        }
        Ok(mpi_buf)
    })
}

const OPENPGP_HASH_INSECURE_MD5: i32 = 1;
const OPENPGP_HASH_INSECURE_SHA1: i32 = 2;
const OPENPGP_HASH_INSECURE_RIPEMD160: i32 = 3;
const OPENPGP_HASH_EXPIRIMENTAL_DOUBLE_SHA: i32 = 4;
const OPENPGP_HASH_INSECURE_MD2: i32 = 5;
const OPENPGP_HASH_INSECURE_TIGER192: i32 = 6;
const OPENPGP_HASH_INSECURE_HAVAL_5_160: i32 = 7;
const OPENPGP_HASH_SHA256: i32 = 8;
const OPENPGP_HASH_SHA384: i32 = 9;
const OPENPGP_HASH_SHA512: i32 = 10;
const OPENPGP_HASH_SHA224: i32 = 11;

// Signature subpackets
const SUBPACKET_CREATION_TIME: u8 = 2;
const SUBPACKET_SIG_EXPIRATION_TIME: u8 = 3;
const SUBPACKET_EXPORTABLE: u8 = 4;
const SUBPACKET_TRUST_SIG: u8 = 5;
const SUBPACKET_REGEX: u8 = 6;
const SUBPACKET_REVOCABLE: u8 = 7;
const SUBPACKET_KEY_EXPIRATION_TIME: u8 = 9;
const SUBPACKET_PLACEHOLDER: u8 = 10;
const SUBPACKET_PREFERRED_SYMMETRIC: u8 = 11;
const SUBPACKET_REVOCATION_KEY: u8 = 12;
const SUBPACKET_ISSUER_KEYID: u8 = 16;
const SUBPACKET_NOTATION: u8 = 20;
const SUBPACKET_PREFERRED_HASH: u8 = 21;
const SUBPACKET_PREFERRED_COMPRESSION: u8 = 22;
const SUBPACKET_KEY_SERVER_PREFERENCES: u8 = 23;
const SUBPACKET_PREFERRED_KEY_SERVERS: u8 = 24;
const SUBPACKET_PRIMARY_USER_ID: u8 = 25;
const SUBPACKET_POLICY_URI: u8 = 26;
const SUBPACKET_KEY_FLAGS: u8 = 27;
const SUBPACKET_SIGNER_USER_ID: u8 = 28;
const SUBPACKET_REVOCATION_REASON: u8 = 29;
const SUBPACKET_FEATURES: u8 = 30;
const SUBPACKET_SIGNATURE_TARGET: u8 = 31;
const SUBPACKET_EMBEDDED_SIGNATURE: u8 = 32;
const SUBPACKET_FINGERPRINT: u8 = 33;

/// Return the number of MPIs for the public-key algorithm `alg`, checking it
/// against signature version `sig_version`.  Returns `Err` if the algorithm is
/// invalid or unsupported for the given signature version.
pub fn pkey_alg_mpis(alg: u8, sig_version: u8) -> Result<u8, Error> {
    let is_v4 = match sig_version {
        3 => false,
        4 => true,
        _ => return Err(Error::UnsupportedSignatureVersion),
    };
    match alg {
        OPENPGP_PUBLIC_KEY_LEGACY_RSA_ENCRYPT_ONLY
        | OPENPGP_PUBLIC_KEY_ELGAMAL_ENCRYPT_ONLY
        | OPENPGP_PUBLIC_KEY_INSECURE_ELGAMAL_SIGN_ENCRYPT
        | OPENPGP_PUBLIC_KEY_ECDH
        | OPENPGP_PUBLIC_KEY_DH => Err(Error::InvalidPkeyAlgorithm(alg)),
        OPENPGP_PUBLIC_KEY_RSA | OPENPGP_PUBLIC_KEY_LEGACY_RSA_SIGN_ONLY => Ok(1),
        OPENPGP_PUBLIC_KEY_EDDSA if is_v4 => Ok(2),
        OPENPGP_PUBLIC_KEY_DSA => Ok(2),
        OPENPGP_PUBLIC_KEY_ECDSA if is_v4 => Err(Error::UnsupportedPkeyAlgorithm(alg)),
        OPENPGP_PUBLIC_KEY_ECDSA | OPENPGP_PUBLIC_KEY_EDDSA => {
            Err(Error::PkeyAlgorithmRequiresV4Sig(alg))
        }
        _ => Err(Error::UnknownPkeyAlgorithm(alg)),
    }
}

/// Checks that a hash algorithm is secure; if it is, returns the length (in bytes) of the hash it
/// generates.  If `allow_weak_hashes` is set, also allow MD5, SHA1, and SHA224.
pub fn check_hash_algorithm(hash: i32, allow_weak_hashes: AllowWeakHashes) -> Result<u16, Error> {
    match hash {
        // Okay hash algorithms
        OPENPGP_HASH_SHA256 => Ok(32),
        OPENPGP_HASH_SHA384 => Ok(48),
        OPENPGP_HASH_SHA512 => Ok(64),
        OPENPGP_HASH_SHA224 if allow_weak_hashes == AllowWeakHashes::Yes => Ok(28),
        OPENPGP_HASH_INSECURE_MD5 if allow_weak_hashes == AllowWeakHashes::Yes => Ok(16),
        OPENPGP_HASH_INSECURE_SHA1 if allow_weak_hashes == AllowWeakHashes::Yes => Ok(20),
        // Insecure hash algorithms
        OPENPGP_HASH_INSECURE_SHA1 |
        OPENPGP_HASH_INSECURE_RIPEMD160 |
        OPENPGP_HASH_INSECURE_MD2 |
        OPENPGP_HASH_INSECURE_TIGER192 |
        OPENPGP_HASH_INSECURE_HAVAL_5_160 |
        // SHA224 is secure, but its security level is a bit low
        OPENPGP_HASH_SHA224 => Err(Error::InsecureAlgorithm(hash)),
        // Invalid algorithms
        OPENPGP_HASH_EXPIRIMENTAL_DOUBLE_SHA |
        // Unknown algorithms
        _ => Err(Error::UnsupportedHashAlgorithm(hash)),
    }
}

/// Information about a signature
#[derive(Clone, Debug)]
pub struct SigInfo {
    /// Hash algorithm
    pub hash_alg: u8,
    /// Public-key algorithm
    pub pkey_alg: u8,
    /// Key ID
    pub key_id: [u8; 8],
    /// Fingerprint
    pub fingerprint: Option<[u8; 20]>,
    /// Creation time
    pub creation_time: u32,
    /// Expiration time, if any
    pub expiration_time: Option<u32>,
}

struct InternalSigInfo {
    /// Signer Key ID
    id: Option<[u8; 8]>,
    /// Fingerprint
    fpr: Option<[u8; 20]>,
    /// Creation time
    creation_time: Option<u32>,
    /// Expiration time
    expiration_time: Option<u32>,
}

fn process_subpacket<'a>(
    reader: &mut Reader<'a>,
    time: u32,
    tag: u8,
    id: &mut InternalSigInfo,
) -> Result<(), Error> {
    match tag {
        // Subpackets invalid in this context
        // only valid in self-signature
        SUBPACKET_KEY_EXPIRATION_TIME |
        SUBPACKET_PREFERRED_SYMMETRIC |
        SUBPACKET_PREFERRED_HASH |
        SUBPACKET_PREFERRED_COMPRESSION |
        SUBPACKET_KEY_SERVER_PREFERENCES |
        SUBPACKET_PRIMARY_USER_ID |
        SUBPACKET_PREFERRED_KEY_SERVERS |
        SUBPACKET_FEATURES |
        // only valid on certification
        SUBPACKET_EXPORTABLE |
        SUBPACKET_TRUST_SIG |
        SUBPACKET_REGEX |
        SUBPACKET_REVOCATION_KEY |
        // only valid on certifications or self-signatures
        SUBPACKET_KEY_FLAGS |
        // only valid on revocations
        SUBPACKET_REVOCATION_REASON |
        // not valid on document signatures
        SUBPACKET_SIGNATURE_TARGET |
        // only valid in subkey binding signatures
        SUBPACKET_EMBEDDED_SIGNATURE |
        // RPM doesn’t handle revocation, so this is pointless.
        // GPG only generates this for certifications.
        SUBPACKET_REVOCABLE |
        // useless, not generated
        SUBPACKET_PLACEHOLDER => {
            Err(Error::IllFormedSignature)
        }
        SUBPACKET_SIG_EXPIRATION_TIME => {
            let timestamp = reader.be_u32()?;
            if time != 0 && timestamp < time {
                Err(Error::SignatureExpired)
            } else if core::mem::replace(&mut id.expiration_time, Some(timestamp)).is_some() {
                Err(Error::IllFormedSignature)
            } else {
                Ok(())
            }
        }
        SUBPACKET_CREATION_TIME => {
            let timestamp = reader.be_u32()?;
            if time != 0 && timestamp > time {
                Err(Error::SignatureNotValidYet)
            } else if core::mem::replace(&mut id.creation_time, Some(timestamp)).is_some() {
                Err(Error::IllFormedSignature)
            } else {
                Ok(())
            }
        }
        SUBPACKET_ISSUER_KEYID => {
            if id.id.is_some() {
                return Err(Error::IllFormedSignature);
            }
            let mut res = [0u8; 8];
            res[..].copy_from_slice(reader.get_bytes(8)?);
            id.id = Some(res);
            Ok(())
        }
        // RPM doesn’t care about this, but we do
        SUBPACKET_FINGERPRINT => {
            let b = reader.get_bytes(21)?;
            if b[0] == 4 && id.fpr.is_none() {
                let mut res = [0u8; 20];
                res[..].copy_from_slice(&b[1..]);
                id.fpr = Some(res);
                Ok(())
            } else {
                Err(Error::IllFormedSignature)
            }
        },
        // Ignore this
        SUBPACKET_SIGNER_USER_ID => {
            let l = reader.len();
            reader.get_bytes(l).expect("length correct");
            Ok(())
        }
        // We reject unknown subpackets to make exploits against RPM less likely
        i @ SUBPACKET_NOTATION |
        i @ SUBPACKET_POLICY_URI | i => Err(Error::UnsupportedCriticalSubpacket(i)),
    }
}

/// Parse a signature from a slice
pub fn parse<'a>(
    data: &'a [u8],
    timestamp: u32,
    allow_weak_hashes: AllowWeakHashes,
    expected_type: SignatureType,
) -> Result<SigInfo, Error> {
    Reader::read_all(data, Error::TrailingJunk, |reader| {
        read_signature(reader, timestamp, allow_weak_hashes, expected_type)
    })
}

/// Reads a signature from `reader`
pub fn read_signature<'a>(
    reader: &mut Reader<'a>,
    timestamp: u32,
    allow_weak_hashes: AllowWeakHashes,
    expected_type: SignatureType,
) -> Result<SigInfo, Error> {
    let packet = packet::next(reader)?.ok_or(Error::PrematureEOF)?;
    if packet.tag() != 2 {
        return Err(Error::IllFormedSignature);
    }
    Reader::read_all(packet.contents(), Error::TrailingJunk, |e| {
        parse_packet_body(e, timestamp, allow_weak_hashes, expected_type)
    })
}

fn parse_packet_body<'a>(
    reader: &mut Reader<'a>,
    timestamp: u32,
    allow_weak_hashes: AllowWeakHashes,
    expected_type: SignatureType,
) -> Result<SigInfo, Error> {
    let version = reader.byte()?;
    #[cfg(test)]
    eprintln!("Version is {}", version);
    let pkey_alg;
    let hash_alg;
    let mut key_id: [u8; 8];
    let mut siginfo = InternalSigInfo {
        id: None,
        fpr: None,
        creation_time: None,
        expiration_time: None,
    };
    let check_sig_type = |reader: &mut Reader| {
        let actual_type = reader.byte()?;
        if actual_type == expected_type as u8 {
            Ok(())
        } else {
            Err(Error::WrongSignatureType {
                expected_type,
                actual_type,
            })
        }
    };
    match version {
        3 => {
            if reader.byte()? != 5 {
                return Err(Error::IllFormedSignature);
            }
            check_sig_type(reader)?;
            siginfo.creation_time = Some(reader.be_u32()?);
            key_id = [0u8; 8];
            key_id.copy_from_slice(reader.get_bytes(8)?);
            // Get the public-key algorithm
            pkey_alg = reader.byte()?;
            hash_alg = reader.byte()?;
        }
        4 => {
            // Signature type; we only allow OPENPGP_SIGNATURE_TYPE_BINARY
            check_sig_type(reader)?;
            pkey_alg = reader.byte()?;
            hash_alg = reader.byte()?;
            let hashed_subpackets = reader.be_u16()?;
            Reader::read_all(
                reader.get_bytes(hashed_subpackets as _)?,
                Error::TrailingJunk,
                |reader| {
                    Ok(while !reader.is_empty() {
                        Reader::read_all(
                            get_varlen_bytes(reader)?,
                            Error::TrailingJunk,
                            |reader| {
                                let tag_byte = reader.byte()?;
                                process_subpacket(reader, timestamp, tag_byte & 0x7F, &mut siginfo)
                            },
                        )?
                    })
                },
            )?;
            // The only non-hashed subpacket allowed is the key ID, and only if
            // it has not already been seen.
            key_id = match siginfo.id {
                None => {
                    if reader.get_bytes(4)? == &[0, 10, 9, SUBPACKET_ISSUER_KEYID] {
                        let mut res = [0u8; 8];
                        res.copy_from_slice(&reader.get_bytes(8)?);
                        res
                    } else {
                        return Err(Error::IllFormedSignature);
                    }
                }
                Some(e) => {
                    if reader.be_u16()? == 0 {
                        e
                    } else {
                        return Err(Error::IllFormedSignature);
                    }
                }
            };
            if let Some(s) = siginfo.fpr {
                if s[12..] != key_id[..] {
                    return Err(Error::IllFormedSignature);
                }
            }
        }
        _ => return Err(Error::UnsupportedSignatureVersion),
    }
    let mpis = pkey_alg_mpis(pkey_alg, version)?;
    if i32::from(hash_alg) == OPENPGP_HASH_INSECURE_MD5 {
        return Err(Error::InsecureAlgorithm(hash_alg.into()));
    }
    check_hash_algorithm(hash_alg.into(), allow_weak_hashes)?;
    // Check the creation time
    let creation_time = match siginfo.creation_time {
        Some(t) => t,
        None => return Err(Error::NoCreationTime),
    };
    // Ignore first 16 bits of hash
    reader.get_bytes(2)?;
    // Read the MPIs
    for _ in 0..mpis {
        read_mpi(reader)?;
    }
    Ok(SigInfo {
        hash_alg,
        pkey_alg,
        creation_time,
        expiration_time: siginfo.expiration_time,
        key_id,
        fingerprint: siginfo.fpr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    static EDDSA_SIG: &'static [u8] = include_bytes!("../../data/eddsa.asc");
    #[test]
    fn signature_not_valid_yet() {
        assert_eq!(
            read_signature(
                &mut Reader::new(EDDSA_SIG),
                1611626265,
                AllowWeakHashes::No,
                SignatureType::Binary,
            )
            .unwrap_err(),
            Error::SignatureNotValidYet
        );
    }
    #[test]
    fn md5_rejected() {
        let mut s = EDDSA_SIG.to_owned();
        s[5] = OPENPGP_HASH_INSECURE_MD5 as _;
        assert_eq!(
            read_signature(
                &mut Reader::new(&s[..]),
                1611626266,
                AllowWeakHashes::No,
                SignatureType::Binary,
            )
            .unwrap_err(),
            Error::InsecureAlgorithm(OPENPGP_HASH_INSECURE_MD5 as _)
        );
        assert_eq!(
            read_signature(
                &mut Reader::new(&s[..]),
                1611626266,
                AllowWeakHashes::Yes,
                SignatureType::Binary,
            )
            .unwrap_err(),
            Error::InsecureAlgorithm(OPENPGP_HASH_INSECURE_MD5 as _)
        );
    }
    #[test]
    fn bad_sig_alg() {
        let mut s = EDDSA_SIG.to_owned();
        s[5] = 255;
        assert_eq!(
            read_signature(
                &mut Reader::new(&s[..]),
                1611626266,
                AllowWeakHashes::Yes,
                SignatureType::Binary,
            )
            .unwrap_err(),
            Error::UnsupportedHashAlgorithm(255)
        );
    }
    #[test]
    fn sha1_rejected() {
        let mut s = EDDSA_SIG.to_owned();
        s[5] = OPENPGP_HASH_INSECURE_SHA1 as _;
        assert_eq!(
            read_signature(
                &mut Reader::new(&s[..]),
                1611626266,
                AllowWeakHashes::No,
                SignatureType::Binary,
            )
            .unwrap_err(),
            Error::InsecureAlgorithm(OPENPGP_HASH_INSECURE_SHA1 as _)
        );
        read_signature(
            &mut Reader::new(&s[..]),
            1611626266,
            AllowWeakHashes::Yes,
            SignatureType::Binary,
        )
        .unwrap();
    }
    #[test]
    fn parses_real_world_sig() {
        static TRAILING_JUNK: &'static [u8] = include_bytes!("../../data/trailing-junk.asc");
        assert_eq!(TRAILING_JUNK.len(), EDDSA_SIG.len() + 1);
        assert_eq!(
            Reader::read_all(TRAILING_JUNK, Error::TrailingJunk, |r| read_signature(
                r,
                0,
                AllowWeakHashes::No,
                SignatureType::Binary,
            )
            .map(drop))
            .unwrap_err(),
            Error::TrailingJunk
        );
        assert_eq!(
            read_signature(
                &mut Reader::new(&EDDSA_SIG[..EDDSA_SIG.len() - 1]),
                0,
                AllowWeakHashes::No,
                SignatureType::Binary,
            )
            .unwrap_err(),
            Error::PrematureEOF
        );
        assert_eq!(
            read_signature(
                &mut Reader::new(EDDSA_SIG),
                0,
                AllowWeakHashes::No,
                SignatureType::Text,
            )
            .unwrap_err(),
            Error::WrongSignatureType {
                expected_type: SignatureType::Text,
                actual_type: 0,
            }
        );
        let sig = read_signature(
            &mut Reader::new(EDDSA_SIG),
            0,
            AllowWeakHashes::No,
            SignatureType::Binary,
        )
        .unwrap();
        assert_eq!(&sig.key_id[..], b"\x28\xA4\x5C\x93\xB0\xB5\xB6\xE0");
        assert_eq!(sig.creation_time, 1611626266);
        assert!(sig.expiration_time.is_none());
        assert_eq!(sig.fingerprint.unwrap()[12..], sig.key_id[..]);
    }
    #[test]
    fn mpi_too_short() {
        let mut buf: Reader = Reader::new(b"\x00\x09\xFF");
        assert_eq!(buf.len(), 3);
        assert_eq!(read_mpi(&mut buf).unwrap_err(), Error::PrematureEOF);
        assert_eq!(buf.len(), 3);
    }
    #[test]
    fn mpi_invalid() {
        for i in 0..255 {
            let s = &[0, i, 0x7F, 0x00];
            let mut buf: Reader = Reader::new(s);
            assert_eq!(buf.len(), 4);
            if i == 7 {
                read_mpi(&mut buf).unwrap();
                assert_eq!(buf.len(), 1);
            } else if i == 15 {
                read_mpi(&mut buf).unwrap();
                assert_eq!(buf.len(), 0);
            } else if i > 16 {
                assert_eq!(read_mpi(&mut buf).unwrap_err(), Error::PrematureEOF);
                assert_eq!(buf.len(), 4);
            } else {
                assert_eq!(read_mpi(&mut buf).unwrap_err(), Error::BadMPI);
                assert_eq!(buf.len(), 4);
            }
        }
    }
    #[test]
    fn wrong_signature_version() {
        for i in 0u16..256 {
            let i = i as u8;
            let e = if i == 3 || i == 4 {
                Error::PrematureEOF
            } else {
                Error::UnsupportedSignatureVersion
            };
            assert_eq!(
                parse_packet_body(
                    &mut Reader::new(&[i]),
                    0,
                    AllowWeakHashes::No,
                    SignatureType::Binary
                )
                .unwrap_err(),
                e
            );
        }
    }
}
