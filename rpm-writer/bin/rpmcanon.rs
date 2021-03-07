use openpgp_parser::AllowWeakHashes;
use rpm_crypto::transaction::RpmTransactionSet;
use rpm_writer::{HeaderBuilder, HeaderEntry};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{copy, Result, Seek, SeekFrom, Write};
use std::os::unix::{
    ffi::OsStrExt,
    fs::OpenOptionsExt,
    io::{AsRawFd, FromRawFd, RawFd},
};
use std::path::Path;

fn main() {
    std::process::exit(inner_main())
}
const RPMTAG_SIG_BASE: u32 = 256;
const RPMSIGTAG_SHA256HEADER: u32 = RPMTAG_SIG_BASE + 17;
const RPMSIGTAG_RSAHEADER: u32 = RPMTAG_SIG_BASE + 12;

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

fn process_file(
    tx: &RpmTransactionSet,
    src: &std::ffi::OsStr,
    dst: &std::ffi::OsStr,
    allow_sha1_sha224: AllowWeakHashes,
    allow_old_pkgs: bool,
    token: rpm_crypto::InitToken,
) -> Result<()> {
    let mut s = File::open(src)?;
    // Ignore the lead
    let _ = rpm_parser::read_lead(&mut s)?;
    // Read the signature header
    let mut sig_header = rpm_parser::load_signature(&mut s, allow_sha1_sha224, token)?;
    let (immutable, _tag, sig, main_header_bytes, hdr_digest) = rpm_parser::verify_package(
        &mut s,
        &mut sig_header,
        &tx.keyring(),
        allow_old_pkgs,
        token,
    )?;
    let magic_offset = 96;
    let mut hdr = HeaderBuilder::new(rpm_writer::HeaderKind::Signature);
    hdr.push(
        RPMSIGTAG_SHA256HEADER,
        HeaderEntry::String(
            CStr::from_bytes_with_nul(&hdr_digest).expect("RPM NUL-terminates its hex data"),
        ),
    );
    hdr.push(RPMSIGTAG_RSAHEADER, HeaderEntry::Bin(&*sig));
    let mut out_data = vec![0; magic_offset];
    out_data[..magic_offset].copy_from_slice(&immutable.lead());
    hdr.emit(&mut out_data).expect("writes to a vec never fail");
    let fixup = (out_data.len() + 7 & !7) - out_data.len();
    out_data.extend_from_slice(&[0u8; 7][..fixup]);
    #[cfg(debug_assertions)]
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
    let token = rpm_crypto::init();
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
    let tx = RpmTransactionSet::new(token);
    if directory {
        todo!()
    }
    match process_file(&tx, &src, &dst, allow_sha1_sha224, allow_old_pkgs, token) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error canonicalizing file: {}", e);
            1
        }
    }
}
