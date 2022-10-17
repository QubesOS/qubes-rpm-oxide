//! RPM package verification

use super::SignatureHeader;
use openpgp_parser;
use rpm_crypto::transaction::RpmKeyring;
use rpm_crypto::{DigestCtx, InitToken};
use std;
use std::convert::TryInto;
use std::io::{copy, Error, ErrorKind, Read, Result, Write};

mod validator;

/// Package verification result
pub struct VerifyResult {
    /// The package main header
    pub main_header: super::MainHeader,
    /// The header+payload signature.  [`None`] if no such signature should be
    /// written.  If such a signature is present in the original package, it
    /// will be verified even if this is not necessary, but this field will
    /// still be [`None`].
    pub header_payload_sig: Option<Vec<u8>>,
    /// The header signature.  This library requires header signatures.
    pub header_sig: Vec<u8>,
    /// The bytes of the main header
    pub main_header_bytes: Vec<u8>,
    /// The SHA1 hash of the main header, hex-encoded with a trailing NUL
    pub main_header_sha1_hash: Vec<u8>,
    /// The SHA256 hash of the main header, hex-encoded with a trailing NUL
    pub main_header_sha256_hash: Vec<u8>,
    /// The MD5 header+payload digest (yuck!).  Will only be [`Some`] for old
    /// packages with no payload digests.
    pub header_payload_weak_digest: Option<Vec<u8>>,
}

/// Verify a package
///
/// # Parameters
///
/// - `src`: The source of the package
/// - `sig_header`: The signature header
/// - `keyring`: The RPM keyring for verification
/// - `allow_old_pkgs`: Allow packages without payload digests?
/// - `preserve_old_sig`: Preserve the header+payload signature?
/// - `token`: Token to prove that RPM has been initialized
/// - `output`: Output stream that receives the (not yet validated!) bytes, for
///   streaming support.
pub fn verify_package(
    src: &mut dyn Read,
    sig_header: &mut SignatureHeader,
    keyring: &RpmKeyring,
    allow_old_pkgs: bool,
    preserve_old_sig: bool,
    token: InitToken,
    mut cb: Option<&mut dyn FnMut(&VerifyResult, Option<&mut dyn Write>) -> Result<()>>,
    output: Option<&mut dyn Write>,
) -> std::io::Result<VerifyResult> {
    use self::validator::Validator;
    let mut validator: Validator<'_> = Validator::new(None);
    let mut header_payload_sig = None;
    let mut header_payload_weak_digest = None;
    if let Some((sig, s_bytes)) = sig_header.header_payload_signature.take() {
        validator.add_signature(sig);
        header_payload_sig = Some(s_bytes);
    } else if preserve_old_sig {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Payload signature requested but not found",
        ));
    }

    if let Some(weak_digest) = sig_header.header_payload_weak_digest.take() {
        header_payload_weak_digest = Some(weak_digest.1.clone());
        validator.add_untrusted_digest(weak_digest.0, weak_digest.1);
    }

    let mut prelude = [0u8; 16];

    // Read the prelude of the main header
    let (index_length, data_length) = {
        src.read_exact(&mut prelude)?;
        super::parse_header_magic(&mut prelude)?
    };

    let main_header_bytes = {
        // Add 1 for the header prelude
        let mut main_header_bytes: Vec<u8> =
            vec![0u8; (16 * (index_length + 1) + data_length).try_into().unwrap()];
        main_header_bytes[..16].copy_from_slice(&prelude);
        src.read_exact(&mut main_header_bytes[16..])?;
        main_header_bytes
    };
    let main_header_sha256_hash = {
        let mut main_header_hash = DigestCtx::init(8, openpgp_parser::AllowWeakHashes::No, token)
            .expect("SHA-256 is supported");
        main_header_hash.update(&main_header_bytes);
        main_header_hash.finalize(true)
    };
    let main_header_sha1_hash = {
        let mut main_header_hash = DigestCtx::init(2, openpgp_parser::AllowWeakHashes::Yes, token)
            .expect("SHA-1 is supported");
        main_header_hash.update(&main_header_bytes);
        main_header_hash.finalize(true)
    };
    assert_eq!(
        validator.write(&main_header_bytes).unwrap(),
        main_header_bytes.len()
    );
    let (mut signature, header_sig) = sig_header
        .header_signature
        .take()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "header not signed"))?;
    signature.update(&main_header_bytes);
    keyring.validate_sig(signature).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            match e {
                2 => "Signature forged!",
                3 => "Key not trusted!",
                4 => "No key available!",
                _ => panic!("bad RPM retval"),
            },
        )
    })?;
    let s: Option<(DigestCtx, Vec<u8>)> = sig_header.header_sha1_hash.take();
    for i in vec![s, sig_header.header_sha256_hash.take()].into_iter() {
        let i: Option<(DigestCtx, Vec<u8>)> = i;
        if let Some((mut ctx, value)) = i {
            ctx.update(&main_header_bytes);
            if ctx.finalize(true) != value {
                return Err(Error::new(ErrorKind::InvalidData, "bad digest"));
            }
        }
    }
    validator.set_output(output);
    let main_header = super::load_immutable(&mut &*main_header_bytes, token)?;
    // This header is signed, so its payload digest is trusted
    match main_header.payload_digest() {
        Ok(s) => {
            header_payload_weak_digest = None;
            if preserve_old_sig {
                validator.add_untrusted_digest(s.0, s.1);
            } else {
                header_payload_sig = None;
                validator.add_trusted_digest(s.0, s.1);
            }
        }
        Err(_) if allow_old_pkgs => {
            if header_payload_sig.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Header signed, but no header+payload signature or payload digest?",
                ));
            } else if header_payload_weak_digest.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "No digest on the payload",
                ));
            }
        }
        Err(e) => return Err(e),
    };
    let vfy_result = VerifyResult {
        main_header,
        header_payload_sig,
        header_sig,
        main_header_bytes,
        main_header_sha1_hash,
        main_header_sha256_hash,
        header_payload_weak_digest,
    };
    if let Some(ref mut cb) = cb {
        let mut output = validator.set_output(None);
        match output {
            None => cb(&vfy_result, None)?,
            Some(ref mut o) => cb(&vfy_result, Some(o))?,
        }
        validator.set_output(output);
    }
    drop(cb);
    copy(src, &mut validator)?;
    validator.validate(&keyring).map_err(|()| {
        Error::new(
            ErrorKind::InvalidData,
            "Package is corrupt - network problem?",
        )
    })?;
    Ok(vfy_result)
}

#[cfg(test)]
mod tests {
    use rpm_crypto;
    use rpm_crypto::transaction::{RpmKeyring, RpmTransactionSet};
    use rpm_crypto::InitToken;
    thread_local! {
        static KEYRING: RpmKeyring = {
            let tx = TOKEN.with(|&s|RpmTransactionSet::new(s));
            tx.expect("cannot load keyring?").keyring()
        };
        static TOKEN: InitToken = rpm_crypto::init(None);
        static SHA256: DigestCtx = TOKEN.with(|&t|DigestCtx::init(8, openpgp_parser::AllowWeakHashes::No,t))
            .expect("SHA-256 is supported");
    }
    use super::validator::Validator;
    use super::*;
    const EMPTY_SHA256: &'static [u8] =
        &*b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\0";
    const A_SHA256: &'static [u8] =
        &*b"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\0";
    fn globals() -> (RpmKeyring, InitToken, DigestCtx) {
        KEYRING.with(|keyring| {
            TOKEN.with(|token| {
                SHA256.with(|sha256| (keyring.clone(), token.clone(), sha256.clone()))
            })
        })
    }
    #[test]
    fn empty_validator_bad() {
        let (keyring, _, _) = globals();
        assert!(Validator::new(None).validate(&keyring).is_err());
    }

    #[test]
    fn untrusted_digest_not_sufficient() {
        let (keyring, _, sha256) = globals();
        let mut v = Validator::new(None);
        v.add_untrusted_digest(sha256.clone(), EMPTY_SHA256.to_owned());
        v.validate(&keyring).unwrap_err();
    }

    #[test]
    fn trusted_digest_sufficient() {
        let (keyring, _, sha256) = globals();
        let mut v = Validator::new(None);
        v.add_trusted_digest(sha256.clone(), EMPTY_SHA256.to_owned());
        v.validate(&keyring).unwrap();
    }

    #[test]
    fn bad_trusted_digest() {
        let (keyring, _, sha256) = globals();
        let mut v = Validator::new(None);
        v.add_trusted_digest(sha256.clone(), EMPTY_SHA256.to_owned());
        assert_eq!(v.write(b"a").unwrap(), 1);
        v.validate(&keyring).unwrap_err();
    }

    #[test]
    fn bad_untrusted_digest() {
        let (keyring, _, sha256) = globals();
        let mut v = Validator::new(None);
        v.add_trusted_digest(sha256.clone(), EMPTY_SHA256.to_owned());
        v.add_untrusted_digest(sha256.clone(), vec![]);
        v.validate(&keyring).unwrap_err();
    }

    #[test]
    fn mixed_digests() {
        let (keyring, _, sha256) = globals();

        // Mixture of digests
        let mut v = Validator::new(None);
        v.add_untrusted_digest(sha256.clone(), A_SHA256.to_owned());
        v.add_trusted_digest(sha256.clone(), EMPTY_SHA256.to_owned());
        v.validate(&keyring).unwrap_err();
    }

    #[test]
    fn mixed_digests_update() {
        let (keyring, _, sha256) = globals();
        // Mixture of digests
        let mut v = Validator::new(None);
        v.add_untrusted_digest(sha256.clone(), A_SHA256.to_owned());
        v.write(b"a").unwrap();
        v.add_trusted_digest(sha256.clone(), EMPTY_SHA256.to_owned());
        v.validate(&keyring).unwrap();
    }

    #[test]
    fn short_writes() {
        let (keyring, _, sha256) = globals();
        // Short writes
        let mut buf = [1];
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        let mut v = Validator::new(Some(&mut cursor));
        v.add_untrusted_digest(sha256.clone(), A_SHA256.to_owned());
        assert_eq!(v.write(b"ab").unwrap(), 1);
        v.add_trusted_digest(sha256.clone(), EMPTY_SHA256.to_owned());
        v.validate(&keyring).unwrap();
    }
}
