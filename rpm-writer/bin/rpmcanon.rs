use openpgp_parser::AllowWeakHashes;
use rpm_parser::{DigestCtx, TagData, TagType};
use rpm_writer::{HeaderEntry, HeaderBuilder};
use std::ffi::CStr;
use std::convert::TryInto;
use std::fs::File;
use std::io::{copy, Error, ErrorKind, Read, Result, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;

fn main() {
    std::process::exit(inner_main())
}

fn usage(success: bool) -> i32 {
    const USAGE: &'static str = "Usage: rpmcanon [OPTIONS] -- SOURCE DESTINATION\n\n\
                                 Options:\n\n\
                                 --help print this message\n\
                                 --insecure-skip-sigcheck skip signature checks\n\
                                 --allow-sha1-sha224 allow packages signed with SHA-1 or SHA-224\n\
                                 --allow-old-pkgs allow packages that don’t have a payload digest in the main header\n\
                                 --directory copy packages in SOURCE to DESTINATION; both directories must exist";
    if success {
        println!("{}", USAGE);
        0
    } else {
        eprintln!("{}", USAGE);
        1
    }
}

fn reserialize_parsed_sig(body: &[u8]) -> Vec<u8> {
    openpgp_parser::packet::next(&mut openpgp_parser::Reader::new(body))
        .expect("already parsed")
        .expect("already parsed")
        .serialize()
}

struct Validator {
    sig: Option<rpm_parser::Signature>,
    dgst: Option<(rpm_parser::DigestCtx, Vec<u8>)>,
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
    fn validate(self, keyring: &rpm_parser::RpmKeyring) -> std::result::Result<(), ()> {
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

const RPMTAG_SHA256HEADER: u32 = 256 + 17;
const RPMSIGTAG_RSAHEADER: u32 = 256 + 12;
const RPMSIGTAG_GPG: u32 = 1005;

fn verify_package(
    src: &mut std::fs::File,
    sig_header: &mut rpm_parser::SignatureHeader,
    keyring: &rpm_parser::RpmKeyring,
    allow_old_pkgs: bool,
    token: rpm_parser::InitToken,
) -> Result<(rpm_parser::MainHeader, u32, Vec<u8>, Vec<u8>, Vec<u8>)> {
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
            untrusted_sig_body = reserialize_parsed_sig(&s_bytes);
        }
    }
    let mut prelude = [0u8; 16];

    // Read the prelude of the main header
    let (index_length, data_length) = {
        src.read_exact(&mut prelude)?;
        rpm_parser::parse_header_magic(&mut prelude)?
    };

    let main_header_bytes = {
        let mut main_header_bytes: Vec<u8> =
            vec![0u8; (16 * (index_length + 1) + data_length).try_into().unwrap()];
        main_header_bytes[..16].copy_from_slice(&prelude);
        src.read_exact(&mut main_header_bytes[16..])?;
        main_header_bytes
    };
    let hdr_digest = {
        let mut hdr_digest =
            DigestCtx::init(8, AllowWeakHashes::No, token).expect("SHA-256 is supported");
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
    let main_header = rpm_parser::load_immutable(&mut &*main_header_bytes, token)?;
    // This header is signed, so its payload digest is trusted
    validator.dgst = match main_header.payload_digest() {
        Ok(s) => {
            untrusted_sig_body = reserialize_parsed_sig(&sig_bytes);
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

fn process_file(
    tx: &rpm_parser::RpmTransactionSet,
    src: &std::ffi::OsStr,
    dst: &std::ffi::OsStr,
    allow_sha1_sha224: AllowWeakHashes,
    _sigcheck: bool,
    allow_old_pkgs: bool,
    token: rpm_parser::InitToken,
) -> Result<()> {
    let mut s = File::open(src)?;
    // Ignore the lead
    let _ = rpm_parser::read_lead(&mut s)?;
    // Read the signature header
    let mut sig_header = rpm_parser::load_signature(&mut s, allow_sha1_sha224, token)?;
    let (immutable, tag, sig, main_header_bytes, hdr_digest) = verify_package(
        &mut s,
        &mut sig_header,
        &tx.keyring(),
        allow_old_pkgs,
        token,
    )?;
    // 167 = 96 + 16 + 16 + 16 + 16 + 16 + 65 + 7
    let magic_offset = 96;
    let mut hdr = HeaderBuilder::new(rpm_writer::HeaderKind::Signature);
    hdr.push(RPMTAG_SHA256HEADER, HeaderEntry::String(CStr::from_bytes_with_nul(&hdr_digest).expect("RPM NUL-terminates its hex data")));
    hdr.push(RPMSIGTAG_RSAHEADER, HeaderEntry::Bin(&*sig));
    let mut out_data = vec![0; magic_offset];
    out_data[..magic_offset].copy_from_slice(&immutable.lead());
    hdr.emit(&mut out_data).expect("writes to a vec never fail");
    let fixup = (out_data.len() + 7 & !7) - out_data.len();
    out_data.extend_from_slice(&[0u8; 7][..fixup]);
    rpm_parser::load_signature(&mut &out_data[magic_offset..], allow_sha1_sha224, token).unwrap();
    let mut dest = File::create(dst)?;
    dest.write_all(&out_data)?;
    dest.write_all(&main_header_bytes)?;
    s.seek(SeekFrom::Start(
        (96 + 16
            + 16 * sig_header.header.index.len()
            + ((7 + sig_header.header.data.len()) & !7)
            + main_header_bytes.len()) as _,
    ))?;
    copy(&mut s, &mut dest)?;
    Ok(())
}

fn inner_main() -> i32 {
    let token = rpm_parser::init();
    let mut args = std::env::args_os().into_iter();
    let mut allow_sha1_sha224 = AllowWeakHashes::No;
    let mut allow_old_pkgs = false;
    let mut directory = false;
    let mut sigcheck = true;
    let _ = match args.next() {
        Some(s) => s,
        None => return usage(false),
    };
    for i in &mut args {
        match i.as_bytes() {
            b"--allow-sha1-sha224" => allow_sha1_sha224 = AllowWeakHashes::Yes,
            b"--help" => return usage(true),
            b"--directory" => directory = true,
            b"--allow-old-pkgs" => allow_old_pkgs = true,
            b"--insecure-skip-sigcheck" => sigcheck = false,
            b"--" => break,
            _ => return usage(false),
        }
    }
    let args: Vec<_> = args.collect();
    if args.len() != 2 {
        return usage(false);
    }
    let (src, dst) = (args[0].clone(), args[1].clone());
    let tx = rpm_parser::RpmTransactionSet::new(token);
    if directory {
        todo!()
    }
    match process_file(
        &tx,
        &src,
        &dst,
        allow_sha1_sha224,
        sigcheck,
        allow_old_pkgs,
        token,
    ) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error canonicalizing file: {}", e);
            1
        }
    }
}
