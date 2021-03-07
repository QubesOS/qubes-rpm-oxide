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

const RPMSIGTAG_RSAHEADER: u32 = 256 + 12;
const RPMSIGTAG_GPG: u32 = 1005;

pub fn verify_package(
    src: &mut std::fs::File,
    sig_header: &mut SignatureHeader,
    keyring: &RpmKeyring,
    allow_old_pkgs: bool,
    token: InitToken,
) -> std::io::Result<(crate::MainHeader, u32, Vec<u8>, Vec<u8>, Vec<u8>)> {
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
    let mut untrusted_sig_body = vec![];
    if allow_old_pkgs {
        if let Some((sig, s_bytes)) = sig_header.header_payload_signature.take() {
            validator.sig = Some(sig);
            untrusted_sig_body = s_bytes;
        }
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
    let hdr_digest = {
        let mut hdr_digest = DigestCtx::init(8, openpgp_parser::AllowWeakHashes::No, token)
            .expect("SHA-256 is supported");
        hdr_digest.update(&main_header_bytes);
        hdr_digest.finalize(true)
    };
    assert_eq!(
        validator.write(&main_header_bytes).unwrap(),
        main_header_bytes.len()
    );
    let mut output_sig_tag = RPMSIGTAG_GPG;
    let (mut signature, sig_bytes) = sig_header
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
            untrusted_sig_body = sig_bytes;
            output_sig_tag = RPMSIGTAG_RSAHEADER;
            Some(s)
        }
        Err(_) if allow_old_pkgs => None,
        Err(e) => return Err(e),
    };
    copy(src, &mut validator)?;
    validator
        .validate(&keyring)
        .map_err(|()| Error::new(ErrorKind::InvalidData, "Payload forged!"))?;
    Ok((
        main_header,
        output_sig_tag,
        untrusted_sig_body,
        main_header_bytes,
        hdr_digest,
    ))
}
