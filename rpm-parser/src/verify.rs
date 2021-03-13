//! RPM package verification

use crate::SignatureHeader;
use rpm_crypto::{transaction::RpmKeyring, DigestCtx, InitToken, Signature};
use std::convert::TryInto;
use std::io::{copy, Error, ErrorKind, Read, Result, Write};

mod validator {
    use super::*;
    /// Something that can be cryptographically verified
    enum Verifyable {
        /// An untrusted digest
        UntrustedDigest(DigestCtx, Vec<u8>),
        /// A signature
        Signature(Signature),
        /// A trusted digest
        TrustedDigest(DigestCtx, Vec<u8>),
    }

    impl Verifyable {
        fn update(&mut self, data: &[u8]) {
            match self {
                Self::UntrustedDigest(dgst, _) | Self::TrustedDigest(dgst, _) => dgst.update(data),
                Self::Signature(sig) => sig.update(data),
            }
        }

        fn trusted(&self) -> bool {
            match self {
                Self::Signature(_) | Self::TrustedDigest(_, _) => true,
                Self::UntrustedDigest(_, _) => false,
            }
        }
    }

    pub(super) struct Validator<'a> {
        objects: Vec<Verifyable>,
        output: Option<&'a mut dyn Write>,
    }

    impl<'a> Write for Validator<'a> {
        /// Update the digests and signatures within with the provided data.
        fn write(&mut self, data: &[u8]) -> Result<usize> {
            let len = match self.output {
                None => data.len(),
                Some(ref mut output) => output.write(data)?,
            };
            for i in &mut self.objects {
                i.update(&data[..len])
            }
            Ok(len)
        }
        fn flush(&mut self) -> Result<()> {
            match self.output {
                None => Ok(()),
                Some(ref mut s) => s.flush(),
            }
        }
    }

    impl<'a> Validator<'a> {
        /// Creates a [`Validator`]
        pub(super) fn new(output: Option<&'a mut dyn Write>) -> Self {
            Self {
                objects: vec![],
                output,
            }
        }

        /// Sets the [`std::io::Write`] that this [`Validator`] will write bytes to.  The bytes are
        /// untrusted at this point.
        ///
        /// Returns the old writer.
        pub(super) fn set_output(
            &mut self,
            output: Option<&'a mut dyn Write>,
        ) -> Option<&'a mut dyn Write> {
            std::mem::replace(&mut self.output, output)
        }

        /// Add an untrusted digest.  An incorrect untrusted digest will result in verification
        /// failure, but a correct untrusted digest is not sufficient.
        pub(super) fn add_untrusted_digest(&mut self, dgst: DigestCtx, data: Vec<u8>) -> &mut Self {
            self.objects.push(Verifyable::UntrustedDigest(dgst, data));
            self
        }

        /// Add a signature.  Signatures are always considered trusted.
        pub(super) fn add_signature(&mut self, sig: Signature) -> &mut Self {
            self.objects.push(Verifyable::Signature(sig));
            self
        }

        /// Add a trusted digest.  Trusted digests are considered to be as strong as a signature.
        /// Therefore, the data being verified must come from a trusted source.
        ///
        /// For example, it is safe to use a digest that comes from a header signed with a trusted
        /// signature.
        pub(super) fn add_trusted_digest(&mut self, dgst: DigestCtx, data: Vec<u8>) -> &mut Self {
            self.objects.push(Verifyable::TrustedDigest(dgst, data));
            self
        }

        /// Consume [`self`] and validate the signatures and/or digests contained theirin.
        ///
        /// This will return [`Ok`] only if both of the following conditions are met:
        ///
        /// - All digests and signatures must validate correctly.
        /// - [`self`] must contain either a signature or a trusted digest.
        pub(super) fn validate(self, keyring: &RpmKeyring) -> std::result::Result<(), ()> {
            let mut trusted = false;
            let mut no_bad_found = true;
            for i in self.objects.into_iter() {
                trusted |= i.trusted();
                no_bad_found &= match i {
                    Verifyable::TrustedDigest(ctx, digest)
                    | Verifyable::UntrustedDigest(ctx, digest) => ctx.finalize(true) == digest,
                    Verifyable::Signature(sig) => keyring.validate_sig(sig).is_ok(),
                };
            }
            if trusted && no_bad_found {
                Ok(())
            } else {
                Err(())
            }
        }
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
    use validator::Validator;
    let mut validator: Validator = Validator::new(None);
    let mut header_payload_sig = None;
    if let Some((sig, s_bytes)) = sig_header.header_payload_signature.take() {
        validator.add_signature(sig);
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
        // Add 1 for the header prelude
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
    validator.set_output(output);
    let main_header = crate::load_immutable(&mut &*main_header_bytes, token)?;
    // This header is signed, so its payload digest is trusted
    match main_header.payload_digest() {
        Ok(s) => {
            if preserve_old_sig {
                validator.add_untrusted_digest(s.0, s.1);
            } else {
                header_payload_sig = None;
                validator.add_trusted_digest(s.0, s.1);
            }
        }
        Err(_) if allow_old_pkgs => {}
        Err(e) => return Err(e),
    };
    let vfy_result = VerifyResult {
        main_header,
        header_payload_sig,
        header_sig,
        main_header_bytes,
        main_header_hash,
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
    validator
        .validate(&keyring)
        .map_err(|()| Error::new(ErrorKind::InvalidData, "Payload forged!"))?;
    Ok(vfy_result)
}

#[cfg(test)]
mod tests {
    use rpm_crypto::{
        transaction::{RpmKeyring, RpmTransactionSet},
        InitToken,
    };
    thread_local! {
        static KEYRING: RpmKeyring = {
            let tx = TOKEN.with(|&s|RpmTransactionSet::new(s));
            tx.keyring()
        };
        static TOKEN: InitToken = rpm_crypto::init();
        static SHA256: DigestCtx = TOKEN.with(|&t|DigestCtx::init(8, openpgp_parser::AllowWeakHashes::No,t))
            .expect("SHA-256 is supported");
    }
    use super::*;
    use validator::Validator;
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
        assert!(matches!(v.write(b"a"), Ok(1)));
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
