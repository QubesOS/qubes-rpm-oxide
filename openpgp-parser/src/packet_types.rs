//! The various types of OpenPGP packets

use super::{
    buffer::Reader,
    packet::{self, Subpacket},
    Error,
};
use core::convert::TryFrom;

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

const OPENPGP_HASH_INSECURE_MD5: u8 = 1;
const OPENPGP_HASH_INSECURE_SHA1: u8 = 2;
const OPENPGP_HASH_INSECURE_RIPEMD160: u8 = 3;
const OPENPGP_HASH_RESERVED1: u8 = 4;
const OPENPGP_HASH_RESERVED2: u8 = 5;
const OPENPGP_HASH_RESERVED3: u8 = 6;
const OPENPGP_HASH_RESERVED4: u8 = 7;
const OPENPGP_HASH_SHA256: u8 = 8;
const OPENPGP_HASH_SHA384: u8 = 9;
const OPENPGP_HASH_SHA512: u8 = 10;
const OPENPGP_HASH_SHA224: u8 = 11;

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

fn read_hash_algorithm<'a>(reader: &mut Reader<'a>) -> Result<u8, Error> {
    let hash = reader.byte()?;
    match hash {
        // Okay hash algorithms
        OPENPGP_HASH_SHA256 |
        OPENPGP_HASH_SHA384 |
        OPENPGP_HASH_SHA512 => Ok(hash),
        // Insecure hash algorithms
        OPENPGP_HASH_INSECURE_MD5 |
        OPENPGP_HASH_INSECURE_SHA1 |
        OPENPGP_HASH_INSECURE_RIPEMD160 |
        OPENPGP_HASH_RESERVED1 |
        OPENPGP_HASH_RESERVED2 |
        OPENPGP_HASH_RESERVED3 |
        OPENPGP_HASH_RESERVED4 |
        // SHA224 is secure, but its security level is a bit low
        OPENPGP_HASH_SHA224 => Err(Error::InsecureAlgorithm),
        // Unknown algorithms
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

fn process_subpacket<'a>(
    subpacket: Subpacket<'a>,
    time: u32,
    id: &mut Option<&'a [u8]>,
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
            } else if time == 0 {
                // time = 0 disables time checking
                Ok(())
            } else if tag == SUBPACKET_SIG_EXPIRATION_TIME && timestamp <= time {
                Err(Error::SignatureExpired)
            } else if tag == SUBPACKET_CREATION_TIME && timestamp > time {
                Err(Error::SignatureNotValidYet)
            } else {
                Ok(())
            }
        },
        SUBPACKET_REVOCABLE => match subpacket.contents().as_untrusted_slice() {
            &[0]|&[1] => Ok(()),
            _ =>{
                #[cfg(test)]
                eprintln!("Bad revokable subpacket!");
                Err(Error::IllFormedSignature)
            }
        },
        // RPM doesn’t care about this, but we do
        SUBPACKET_FINGERPRINT => {
            match subpacket.contents().as_untrusted_slice().split_first() {
                Some((4, fpr)) if fpr.len() == 20 && id.is_none() => {
                    #[cfg(test)]
                    eprintln!("Fingerprint is {:?}", fpr);
                    *id = Some(&fpr[12..]);
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
        SUBPACKET_ISSUER_KEYID |
        SUBPACKET_SIGNER_USER_ID | _ => Err(Error::UnsupportedCriticalSubpacket),
    }
}

/// Checks that `reader` holds a valid signature, emptying it if it does.
pub fn read_signature<'a>(reader: &mut Reader<'a>, timestamp: u32) -> Result<(), Error> {
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
    let pkey_algorithm;
    let mpis = match version {
        3 => {
            if reader.byte()? != 5 || reader.byte()? != OPENPGP_SIGNATURE_TYPE_BINARY {
                #[cfg(test)]
                eprintln!("Bad version 3 signature!");
                return Err(Error::IllFormedSignature);
            }
            // Skip the key ID and signature creation time
            reader.get(12)?;
            // Get the public-key algorithm
            pkey_algorithm = reader.byte()?;
            let mpis = match pkey_algorithm {
                OPENPGP_PUBLIC_KEY_RSA => 1,
                OPENPGP_PUBLIC_KEY_DSA => 2,

                // Prohibited algorithm
                OPENPGP_PUBLIC_KEY_INSECURE_ELGAMAL_SIGN_ENCRYPT |
                // ECDSA requires v4 signatures
                OPENPGP_PUBLIC_KEY_ECDSA |
                // Encryption algorithms
                OPENPGP_PUBLIC_KEY_LEGACY_RSA_ENCRYPT_ONLY |
                OPENPGP_PUBLIC_KEY_ELGAMAL_ENCRYPT_ONLY |
                OPENPGP_PUBLIC_KEY_ECDH |
                OPENPGP_PUBLIC_KEY_DH => return Err(Error::InvalidAlgorithm),

                // Unsupported legacy algoritms
                OPENPGP_PUBLIC_KEY_LEGACY_RSA_SIGN_ONLY |
                _ => return Err(Error::UnsupportedAlgorithm),
            };
            read_hash_algorithm(reader)?;
            mpis
        }
        4 => {
            // Signature type; we only allow OPENPGP_SIGNATURE_TYPE_BINARY
            if reader.byte()? != OPENPGP_SIGNATURE_TYPE_BINARY {
                return Err(Error::IllFormedSignature);
            }
            pkey_algorithm = reader.byte()?;
            let mpis = match pkey_algorithm {
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
            eprintln!("Signature algorithm is {}", pkey_algorithm);
            let _hash_algo = read_hash_algorithm(reader)?;
            #[cfg(test)]
            eprintln!("digest algo {}", _hash_algo);
            let mut uid = None;
            packet::get_length_bytes(reader, 2)?.read_all(Error::TrailingJunk, |reader| {
                while let Some(subpacket) = packet::Subpacket::subpacket(reader)? {
                    process_subpacket(subpacket, timestamp, &mut uid)?
                }
                Ok(())
            })?;
            // We treat unhashed subpackets specially: there must be exactly
            // one, and it must be the issuer key ID.  This prevents an attacker
            // from inserting a malicious unhashed subpacket.  We also check
            // that the issuer key ID matches the fingerprint, if one is
            // specified.
            if reader.get(4)?.as_untrusted_slice() != &[0, 10, 9, SUBPACKET_ISSUER_KEYID] {
                return Err(Error::IllFormedSignature);
            }
            let user_id = reader.get(8)?;
            if let Some(uid) = uid {
                if user_id.as_untrusted_slice() != uid {
                    return Err(Error::IllFormedSignature);
                }
            }
            mpis
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
        true => Ok(()),
        false => Err(Error::IllFormedSignature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_real_world_sig() {
        static RPM_PKG_SIG: &'static [u8] = &[
            0x89, 0x02, 0x33, 0x04, 0x00, 0x01, 0x08, 0x00, 0x1d, 0x16, 0x21, 0x04, 0x58, 0x17,
            0xa4, 0x3b, 0x28, 0x3d, 0xe5, 0xa9, 0x18, 0x1a, 0x52, 0x2e, 0x18, 0x48, 0x79, 0x2f,
            0x9e, 0x27, 0x95, 0xe9, 0x05, 0x02, 0x5f, 0xf9, 0x34, 0x4d, 0x00, 0x0a, 0x09, 0x10,
            0x18, 0x48, 0x79, 0x2f, 0x9e, 0x27, 0x95, 0xe9, 0x07, 0xb8, 0x0f, 0xfe, 0x36, 0x97,
            0xd8, 0x46, 0x88, 0x84, 0xa2, 0x52, 0xc3, 0xa1, 0x8c, 0x00, 0xee, 0xd8, 0x78, 0x28,
            0x86, 0x73, 0x61, 0xf6, 0x8b, 0x28, 0x81, 0xb5, 0x1c, 0xd3, 0x3b, 0x4f, 0x0f, 0xea,
            0x8f, 0x41, 0x6a, 0x6a, 0x70, 0xbe, 0x74, 0x83, 0xce, 0x92, 0xc9, 0x3e, 0x4d, 0x6a,
            0x34, 0xb3, 0xf7, 0x2a, 0xf0, 0x59, 0x41, 0xf4, 0xaa, 0x1b, 0x43, 0xb7, 0xcc, 0xcb,
            0xfb, 0x36, 0x14, 0x4d, 0xef, 0x98, 0x56, 0x39, 0x66, 0xa5, 0x8c, 0xdd, 0xca, 0x31,
            0x2d, 0x75, 0x10, 0xc9, 0x2d, 0x7b, 0x6c, 0x6a, 0x13, 0x26, 0x1c, 0x6f, 0x7a, 0x22,
            0x0b, 0x1f, 0x18, 0x74, 0x37, 0xf9, 0xdd, 0xd4, 0xd0, 0xdf, 0x71, 0x4a, 0x52, 0x52,
            0x9c, 0x58, 0xfe, 0x9c, 0x60, 0xf1, 0x2a, 0x80, 0xd1, 0xc1, 0x55, 0x02, 0x54, 0x8b,
            0x22, 0x96, 0x12, 0x02, 0xdf, 0x8c, 0x41, 0xbf, 0xdc, 0x06, 0xa0, 0x3d, 0x89, 0x4f,
            0x83, 0xf6, 0xf1, 0x8b, 0x71, 0x1e, 0xd8, 0xae, 0x9e, 0x71, 0xa7, 0x79, 0xb8, 0xc4,
            0xae, 0xb7, 0x10, 0xe5, 0x4d, 0x0e, 0x91, 0x71, 0xa6, 0xd6, 0x3c, 0xec, 0xda, 0xaa,
            0xd5, 0x3d, 0x26, 0xd7, 0xc5, 0xc3, 0x2b, 0x74, 0xfa, 0xb9, 0xce, 0x5b, 0xdc, 0xc8,
            0xda, 0x90, 0xec, 0x98, 0xa4, 0x4c, 0x9a, 0xcc, 0xb2, 0xd4, 0x76, 0x30, 0xcc, 0x45,
            0xa2, 0x90, 0x8b, 0x10, 0x3f, 0x33, 0x1c, 0x84, 0x88, 0xcd, 0x4c, 0x25, 0xcf, 0xf2,
            0x2d, 0xd4, 0x9a, 0x3f, 0x26, 0x85, 0x5d, 0xd2, 0x24, 0x44, 0x6a, 0x22, 0x2f, 0x61,
            0x9f, 0x89, 0x53, 0x21, 0x72, 0x60, 0xa8, 0xd8, 0x8a, 0x37, 0xeb, 0x87, 0xdd, 0xbb,
            0x4c, 0x0a, 0xe1, 0x43, 0xec, 0xff, 0x44, 0x4d, 0x29, 0x35, 0x96, 0xc4, 0xd2, 0x08,
            0x44, 0x7f, 0xfc, 0x28, 0x13, 0x41, 0x29, 0x65, 0xb8, 0x25, 0x13, 0xe6, 0x6f, 0x3b,
            0xb0, 0x4a, 0xb5, 0x1a, 0x72, 0x58, 0xcf, 0x1a, 0x10, 0x96, 0x69, 0xd5, 0x1b, 0x3d,
            0xbd, 0x7c, 0x74, 0x99, 0x2f, 0xec, 0x64, 0x63, 0x66, 0xe4, 0xb8, 0xf5, 0xb2, 0x62,
            0x1b, 0x75, 0xb7, 0x4d, 0xd5, 0x94, 0x1c, 0xec, 0x3c, 0xa1, 0xb6, 0x68, 0xfc, 0x27,
            0x47, 0x70, 0xd7, 0x60, 0xf3, 0x62, 0xe1, 0x83, 0xf6, 0xab, 0xfc, 0x6c, 0x7d, 0x0b,
            0x2a, 0x2c, 0xb3, 0x5e, 0xb3, 0x81, 0x5a, 0x04, 0x73, 0x27, 0x22, 0x4d, 0x89, 0x0c,
            0xbb, 0x70, 0xbd, 0x69, 0xe6, 0xa8, 0xc0, 0xa0, 0x60, 0x7a, 0xf4, 0x7c, 0x45, 0xc6,
            0xf3, 0x72, 0x9b, 0x19, 0xae, 0xc5, 0xf5, 0x43, 0x2f, 0xc4, 0x93, 0x66, 0x09, 0x83,
            0x27, 0x7a, 0xd3, 0xdf, 0x9c, 0x72, 0xc2, 0x5a, 0xc0, 0xa1, 0xf9, 0x3c, 0x8f, 0x49,
            0x7d, 0xcc, 0x1d, 0x26, 0xc5, 0xad, 0xee, 0x55, 0xcb, 0xd4, 0x35, 0xff, 0xaa, 0x46,
            0xbe, 0x21, 0x58, 0x56, 0x22, 0xee, 0xce, 0x71, 0xad, 0x57, 0x09, 0x68, 0xf7, 0xcb,
            0xc2, 0xc8, 0x08, 0x03, 0x6d, 0x4f, 0x8f, 0xd3, 0xb9, 0x52, 0xe5, 0x05, 0xb7, 0xdc,
            0x60, 0x9d, 0x8c, 0xe3, 0xe3, 0x26, 0x10, 0x93, 0x2a, 0x74, 0x4b, 0x92, 0xe0, 0xb2,
            0xac, 0x0a, 0x05, 0xcc, 0x0e, 0x26, 0x07, 0x7c, 0x92, 0x4a, 0x07, 0xb4, 0x93, 0x98,
            0xdc, 0x0a, 0x8d, 0x80, 0x4c, 0x82, 0xbb, 0x80, 0x42, 0xf1, 0xdd, 0xd5, 0xd9, 0x61,
            0xb7, 0x40, 0x6e, 0x30, 0x0e, 0x18, 0xff, 0x80, 0xea, 0x02, 0xd0, 0x88, 0xa9, 0x02,
            0x3c, 0xc2, 0x27, 0xab, 0x53, 0x53, 0x16, 0x4c, 0xcf, 0x97, 0xd4, 0x5f, 0x64, 0x90,
            0xf5, 0xc5, 0x19, 0x11, 0x3e, 0x8b, 0xca, 0x4a, 0x8f, 0xf6, 0x4e, 0x49, 0x51, 0xca,
            0x50, 0xe1, 0x70, 0xb8, 0x94, 0x3f, 0xd8, 0xd5, 0xef, 0x85, 0x43, 0x3d, 0x90, 0xac,
            0x41, 0x8f, 0xa7, 0x79, 0xae, 0x3a,
        ];
        read_signature(&mut Reader::new(RPM_PKG_SIG), 0).unwrap();
        static EDDSA_SIG: &'static [u8] = include_bytes!("../../eddsa.asc");
        read_signature(&mut Reader::new(EDDSA_SIG), 0).unwrap();
    }
}
