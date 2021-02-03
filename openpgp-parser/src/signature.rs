//! OpenPGP signatures

mod subpacket;

use super::{buffer::Reader, packet, Error};

use core::convert::{TryFrom, TryInto};
pub use subpacket::{Subpacket, SubpacketIterator, Critical};

/// Read a multiprecision integer (MPI) from `reader`.  Value is returned as a
/// `Reader`.
pub fn read_mpi<'a>(reader: &mut Reader<'a>) -> Result<Reader<'a>, Error> {
    reader.read(|reader| {
        let bits = packet::get_be_u32(reader, 2)? + 7;
        let mpi_buf = reader.get(usize::try_from(bits)? >> 3)?;
        // don’t use ‘Reader::byte’, which mutates the reader
        if let Some(first_byte) = mpi_buf.as_untrusted_slice().get(0) {
            // check that there are no spurious leading zeros
            // this is not valid for encrypted MPIs, but we don’t deal with
            // them, as we only parse signatures
            if first_byte.leading_zeros() + (bits & 7) != 7 {
                #[cfg(test)]
                eprintln!(
                    "First byte has {} leading zeros, expected {}",
                    first_byte.leading_zeros(),
                    bits & 7
                );
                return Err(Error::BadMPI);
            }
        }
        Ok(mpi_buf)
    })
}

const OPENPGP_SIGNATURE_TYPE_BINARY: u8 = 0;

const OPENPGP_HASH_INSECURE_MD5: i32 = 1;
const OPENPGP_HASH_INSECURE_SHA1: i32 = 2;
const OPENPGP_HASH_INSECURE_RIPEMD160: i32 = 3;
const OPENPGP_HASH_RESERVED1: i32 = 4;
const OPENPGP_HASH_RESERVED2: i32 = 5;
const OPENPGP_HASH_RESERVED3: i32 = 6;
const OPENPGP_HASH_RESERVED4: i32 = 7;
const OPENPGP_HASH_SHA256: i32 = 8;
const OPENPGP_HASH_SHA384: i32 = 9;
const OPENPGP_HASH_SHA512: i32 = 10;
const OPENPGP_HASH_SHA224: i32 = 11;

// Public key algorithms
const OPENPGP_PUBLIC_KEY_RSA: u8 = 1;
const OPENPGP_PUBLIC_KEY_LEGACY_RSA_ENCRYPT_ONLY: u8 = 2;
const OPENPGP_PUBLIC_KEY_LEGACY_RSA_SIGN_ONLY: u8 = 3;
const OPENPGP_PUBLIC_KEY_ELGAMAL_ENCRYPT_ONLY: u8 = 16;
const OPENPGP_PUBLIC_KEY_DSA: u8 = 17;
const OPENPGP_PUBLIC_KEY_ECDH: u8 = 18;
const OPENPGP_PUBLIC_KEY_ECDSA: u8 = 19;
const OPENPGP_PUBLIC_KEY_INSECURE_ELGAMAL_SIGN_ENCRYPT: u8 = 20;
const OPENPGP_PUBLIC_KEY_DH: u8 = 21;
const OPENPGP_PUBLIC_KEY_EDDSA: u8 = 22;

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

/// Checks that a hash algorithm is secure; if it is, returns the length (in bytes) of the hash it
/// generates.
pub fn check_hash_algorithm(hash: i32) -> Result<u16, Error> {
    match hash {
        // Okay hash algorithms
        OPENPGP_HASH_SHA256 => Ok(32),
        OPENPGP_HASH_SHA384 => Ok(48),
        OPENPGP_HASH_SHA512 => Ok(64),
        // Insecure hash algorithms
        OPENPGP_HASH_INSECURE_MD5 |
        OPENPGP_HASH_INSECURE_SHA1 |
        OPENPGP_HASH_INSECURE_RIPEMD160 |
        // SHA224 is secure, but its security level is a bit low
        OPENPGP_HASH_SHA224 => Err(Error::InsecureAlgorithm),
        // Invalid algorithms
        OPENPGP_HASH_RESERVED1 |
        OPENPGP_HASH_RESERVED2 |
        OPENPGP_HASH_RESERVED3 |
        OPENPGP_HASH_RESERVED4 |
        // Unknown algorithms
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

/// Information about a signature
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SigInfo<'a> {
    /// Hash algorithm
    pub hash_alg: u8,
    /// Public key algorithm
    pub pkey_alg: u8,
    /// Signer Key ID
    pub key_id: [u8; 8],
    /// Creation time
    pub creation_time: Option<u32>,
    /// Expiration time
    pub expiration_time: Option<u32>,
    /// Hashed subpacket iterator
    pub subpackets: SubpacketIterator<'a>,
}

struct InternalSigInfo {
    /// Signer Key ID
    id: Option<[u8; 8]>,
    /// Creation time
    creation_time: Option<u32>,
    /// Expiration time
    expiration_time: Option<u32>,
}

fn process_subpacket<'a>(
    subpacket: Subpacket<'a>,
    time: u32,
    id: &mut InternalSigInfo,
) -> Result<(), Error> {
    let tag = subpacket.tag();
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
        // We require this subpacket to be unhashed
        SUBPACKET_ISSUER_KEYID |
        // useless, not generated
        SUBPACKET_PLACEHOLDER => {
            #[cfg(test)]
            eprintln!("Unsupported packet!");
            Err(Error::IllFormedSignature)
        }
        SUBPACKET_SIG_EXPIRATION_TIME |
        SUBPACKET_CREATION_TIME => {
            let mut buffer = subpacket.contents();
            let timestamp = packet::get_be_u32(&mut buffer, 4)?;
            if !buffer.is_empty() {
                #[cfg(test)]
                eprintln!("Bad timestamp!");
                Err(Error::IllFormedSignature)
            } else if tag == SUBPACKET_SIG_EXPIRATION_TIME {
                if id.expiration_time.is_some() {
                    Err(Error::IllFormedSignature)
                } else if time != 0 && timestamp >= time {
                    Err(Error::SignatureExpired)
                } else {
                    id.expiration_time = Some(timestamp);
                    Ok(())
                }
            } else {
                if id.creation_time.is_some() {
                    Err(Error::IllFormedSignature)
                } else if time != 0 && timestamp < time {
                    Err(Error::SignatureNotValidYet)
                } else {
                    id.creation_time = Some(timestamp);
                    Ok(())
                }
            }
        },
        // RPM doesn’t care about this, but we do
        SUBPACKET_FINGERPRINT => {
            match subpacket.contents().as_untrusted_slice().split_first() {
                Some((4, fpr)) if fpr.len() == 20 && id.id.is_none() => {
                    #[cfg(test)]
                    eprintln!("Fingerprint is {:?}", fpr);
                    id.id = Some(fpr[12..].try_into().expect("length is correct; qed"));
                    Ok(())
                }
                _ => {
                    #[cfg(test)]
                    eprintln!("Bad fingerprint subpacket!");
                    Err(Error::IllFormedSignature)
                }
            }
        }
        // We reject unknown subpackets to make exploits against RPM less likely
        SUBPACKET_NOTATION |
        SUBPACKET_POLICY_URI |
        SUBPACKET_SIGNER_USER_ID | _ => Err(Error::UnsupportedCriticalSubpacket),
    }
}

/// Checks that `reader` holds a valid signature, emptying it if it does.
pub fn read_signature<'a>(reader: &mut Reader<'a>, timestamp: u32) -> Result<SigInfo<'a>, Error> {
    let packet = packet::next(reader)?.ok_or(Error::PrematureEOF)?;
    let tag = packet.tag();
    if tag != 2 {
        #[cfg(test)]
        eprintln!("Tag is {} - this is not a signature!", tag);
        return Err(Error::IllFormedSignature);
    }
    let mut reader = packet.contents();
    let reader = &mut reader;
    let version = reader.byte()?;
    #[cfg(test)]
    eprintln!("Version is {}", version);
    let pkey_alg;
    let hash_alg;
    let key_id: [u8; 8];
    let mut siginfo = InternalSigInfo {
        id: None,
        creation_time: None,
        expiration_time: None,
    };
    let (subpackets, mpis) = match version {
        3 => {
            if reader.byte()? != 5 || reader.byte()? != OPENPGP_SIGNATURE_TYPE_BINARY {
                #[cfg(test)]
                eprintln!("Bad version 3 signature!");
                return Err(Error::IllFormedSignature);
            }
            siginfo.creation_time = Some(reader.be_u32()?);
            key_id = u64::to_le_bytes(reader.le_u64()?);
            // Get the public-key algorithm
            pkey_alg = reader.byte()?;
            let mpis = match pkey_alg {
                OPENPGP_PUBLIC_KEY_RSA => 1,
                OPENPGP_PUBLIC_KEY_DSA => 2,

                // Prohibited algorithm
                OPENPGP_PUBLIC_KEY_INSECURE_ELGAMAL_SIGN_ENCRYPT |
                // ECDSA and EdDSA require v4 signatures
                OPENPGP_PUBLIC_KEY_ECDSA |
                OPENPGP_PUBLIC_KEY_EDDSA |
                // Encryption algorithms
                OPENPGP_PUBLIC_KEY_LEGACY_RSA_ENCRYPT_ONLY |
                OPENPGP_PUBLIC_KEY_ELGAMAL_ENCRYPT_ONLY |
                OPENPGP_PUBLIC_KEY_ECDH |
                OPENPGP_PUBLIC_KEY_DH => return Err(Error::InvalidAlgorithm),

                // Unsupported legacy algoritms
                OPENPGP_PUBLIC_KEY_LEGACY_RSA_SIGN_ONLY |
                _ => return Err(Error::UnsupportedAlgorithm),
            };
            hash_alg = reader.byte()?;
            check_hash_algorithm(hash_alg.into())?;
            let iter = SubpacketIterator::empty();
            (iter, mpis)
        }
        4 => {
            // Signature type; we only allow OPENPGP_SIGNATURE_TYPE_BINARY
            if reader.byte()? != OPENPGP_SIGNATURE_TYPE_BINARY {
                return Err(Error::IllFormedSignature);
            }
            pkey_alg = reader.byte()?;
            let mpis = match pkey_alg {
                OPENPGP_PUBLIC_KEY_RSA => 1,
                // RPM does not support ECDSA
                OPENPGP_PUBLIC_KEY_ECDSA => return Err(Error::UnsupportedAlgorithm),
                OPENPGP_PUBLIC_KEY_EDDSA | OPENPGP_PUBLIC_KEY_DSA => 2,

                // Prohibited algorithm
                OPENPGP_PUBLIC_KEY_INSECURE_ELGAMAL_SIGN_ENCRYPT |
                // Encryption algorithms
                OPENPGP_PUBLIC_KEY_LEGACY_RSA_ENCRYPT_ONLY |
                OPENPGP_PUBLIC_KEY_ELGAMAL_ENCRYPT_ONLY |
                OPENPGP_PUBLIC_KEY_ECDH |
                OPENPGP_PUBLIC_KEY_DH => return Err(Error::InvalidAlgorithm),

                // Unsupported legacy algoritms
                OPENPGP_PUBLIC_KEY_LEGACY_RSA_SIGN_ONLY |
                _ => return Err(Error::UnsupportedAlgorithm),
            };
            #[cfg(test)]
            eprintln!("Signature algorithm is {}", pkey_alg);
            hash_alg = reader.byte()?;
            check_hash_algorithm(hash_alg.into())?;
            #[cfg(test)]
            eprintln!("digest algo {}", hash_alg);
            let subpackets = subpacket::SubpacketIterator::read_u16_prefixed(reader)?;
            for subpacket in subpackets.clone() {
                process_subpacket(subpacket, timestamp, &mut siginfo)?
            }
            // We treat unhashed subpackets specially: there must be exactly
            // one, and it must be the issuer key ID.  This prevents an attacker
            // from inserting a malicious unhashed subpacket.  We also check
            // that the issuer key ID matches the fingerprint, if one is
            // specified.
            if reader.get(4)?.as_untrusted_slice() != &[0, 10, 9, SUBPACKET_ISSUER_KEYID] {
                return Err(Error::IllFormedSignature);
            }
            key_id = u64::to_le_bytes(reader.le_u64()?);
            if siginfo.id.is_some() && siginfo.id != Some(key_id) {
                return Err(Error::IllFormedSignature);
            }
            (subpackets, mpis)
        }
        _ => return Err(Error::IllFormedSignature),
    };
    // Ignore first 16 bits of hash
    reader.get(2)?;
    // Read the MPIs
    for _ in 0..mpis {
        read_mpi(reader)?;
    }
    match reader.is_empty() {
        true => Ok(SigInfo {
            hash_alg,
            pkey_alg,
            creation_time: siginfo.creation_time,
            expiration_time: siginfo.expiration_time,
            key_id,
            subpackets,
        }),
        false => Err(Error::IllFormedSignature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_real_world_sig() {
        static EDDSA_SIG: &'static [u8] = include_bytes!("../../eddsa.asc");
        read_signature(&mut Reader::new(EDDSA_SIG), 0).unwrap();
    }
}
