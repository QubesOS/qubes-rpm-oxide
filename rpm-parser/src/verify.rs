//! RPM package verification

use crate::SignatureHeader;
use rpm_crypto::{transaction::RpmKeyring, DigestCtx, InitToken, Signature};
use std::convert::TryInto;
use std::io::{copy, Error, ErrorKind, Read, Result, Write};

struct Validator {
    sig: Option<Signature>,
    dgst: Option<(DigestCtx, Vec<u8>)>,
}

impl std::io::Write for Validator {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.sig.as_mut().map(|s| s.update(data));
        self.dgst.as_mut().map(|(c, _)| c.update(data));
        Ok(data.len())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Validator {
    fn validate(self, keyring: &RpmKeyring) -> std::result::Result<(), ()> {
        let Self { sig, dgst } = self;
        let mut retval = Err(());
        if let Some(s) = sig {
            let () = keyring.validate_sig(s).map_err(drop)?;
            retval = Ok(());
        }
        if let Some((ctx, digest)) = dgst {
            if ctx.finalize(true) != digest {
                return Err(());
            }
            retval = Ok(())
        }
        retval
    }
}

/// Package verification result
pub struct VerifyResult {
    /// The package main header
    pub main_header: crate::MainHeader,
    /// The header+payload signature.  [`None`] if no such signature should be written.
    /// If such a signature is present in the original package, it will be verified even if this is
    /// not necessary, but this field will still be [`None`].
    pub header_payload_sig: Option<Vec<u8>>,
    /// The header signature.  This library requires header signatures.
    pub header_sig: Vec<u8>,
    /// The bytes of the main header
    pub main_header_bytes: Vec<u8>,
    /// The SHA256 hash of the main header, hex-encoded with a trailing NUL
    pub main_header_hash: Vec<u8>,
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
pub fn verify_package(
    src: &mut std::fs::File,
    sig_header: &mut SignatureHeader,
    keyring: &RpmKeyring,
    allow_old_pkgs: bool,
    preserve_old_sig: bool,
    token: InitToken,
) -> std::io::Result<VerifyResult> {
    assert!(Validator {
        sig: None,
        dgst: None
    }
    .validate(keyring)
    .is_err());
    let mut validator = Validator {
        sig: None,
        dgst: None,
    };
    let mut header_payload_sig = None;
    if let Some((sig, s_bytes)) = sig_header.header_payload_signature.take() {
        validator.sig = Some(sig);
        header_payload_sig = Some(s_bytes);
    } else if preserve_old_sig {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Payload signature requested but not found",
        ));
    }
    let mut prelude = [0u8; 16];

    // Read the prelude of the main header
    let (index_length, data_length) = {
        src.read_exact(&mut prelude)?;
        crate::parse_header_magic(&mut prelude)?
    };

    let main_header_bytes = {
        let mut main_header_bytes: Vec<u8> =
            vec![0u8; (16 * (index_length + 1) + data_length).try_into().unwrap()];
        main_header_bytes[..16].copy_from_slice(&prelude);
        src.read_exact(&mut main_header_bytes[16..])?;
        main_header_bytes
    };
    let main_header_hash = {
        let mut main_header_hash = DigestCtx::init(8, openpgp_parser::AllowWeakHashes::No, token)
            .expect("SHA-256 is supported");
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
    let main_header = crate::load_immutable(&mut &*main_header_bytes, token)?;
    // This header is signed, so its payload digest is trusted
    validator.dgst = match main_header.payload_digest() {
        Ok(s) => {
            if !preserve_old_sig {
                header_payload_sig = None
            }
            Some(s)
        }
        Err(_) if allow_old_pkgs => None,
        Err(e) => return Err(e),
    };
    copy(src, &mut validator)?;
    validator
        .validate(&keyring)
        .map_err(|()| Error::new(ErrorKind::InvalidData, "Payload forged!"))?;
    Ok(VerifyResult {
        main_header,
        header_payload_sig,
        header_sig,
        main_header_bytes,
        main_header_hash,
    })
}
