#![feature(rustc_private)] // hack hack
#![feature(libc)]

#![cfg_attr(bare_trait_obj_deprecated, allow(bare_trait_objects))]
#![cfg_attr(ellipsis_inclusive_range_deprecated, allow(ellipsis_inclusive_range_patterns))]
#![cfg_attr(const_fn_unstable, feature(const_fn))]

#[cfg(any(not(any(const_fn_stable, const_fn_unstable)),
          not(any(bare_trait_obj_deprecated, bare_trait_obj_allowed)),
          not(any(ellipsis_inclusive_range_deprecated, ellipsis_inclusive_range_allowed)),
          not(any(try_from_stable, try_from_unstable))))]
compile_error!("build script bug");

extern crate libc;
extern crate openpgp_parser;
extern crate rpm_crypto;
extern crate rpm_parser;
extern crate rpm_writer;

use openpgp_parser::AllowWeakHashes;
use rpm_crypto::transaction::RpmTransactionSet;
use rpm_writer::{HeaderBuilder, HeaderEntry};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Result, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;

fn main() {
    std::process::exit(inner_main())
}

fn errno() -> std::os::raw::c_int {
    unsafe { *libc::__errno_location() }
}

const RPMTAG_SIG_BASE: u32 = 256;
const RPMSIGTAG_SHA256HEADER: u32 = RPMTAG_SIG_BASE + 17;
const RPMSIGTAG_RSAHEADER: u32 = RPMTAG_SIG_BASE + 12;
const RPMSIGTAG_PGP: u32 = 1002;
const RPMSIGTAG_MD5: u32 = 1004;

fn usage(success: bool) -> i32 {
    const USAGE: &'static str = "Usage: rpmcanon [OPTIONS] -- SOURCE DESTINATION\n\n\
                                 Options:\n\n\
                                 --help print this message\n\
                                 --preserve-old-signature Preserve and require the RPMv3 (header+payload) signature\n\
                                 --allow-weak-hashes allow packages signed with SHA-1 or SHA-224\n\
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

fn emit_header(
    &rpm_parser::VerifyResult {
        ref main_header,
        ref header_payload_sig,
        ref header_sig,
        ref main_header_bytes,
        ref main_header_hash,
        ref header_payload_weak_digest,
    }: &rpm_parser::VerifyResult,
    mut dest: Option<&mut std::io::Write>,
    _allow_weak_hashes: AllowWeakHashes,
    _token: rpm_crypto::InitToken,
) -> std::io::Result<()> {
    let dest = dest.as_mut().expect("we always pass a stream; qed");
    let magic_offset = 96;
    let mut hdr = HeaderBuilder::new(rpm_writer::HeaderKind::Signature);
    hdr.push(
        RPMSIGTAG_SHA256HEADER,
        HeaderEntry::String(
            CStr::from_bytes_with_nul(&main_header_hash).expect("RPM NUL-terminates its hex data"),
        ),
    );
    hdr.push(RPMSIGTAG_RSAHEADER, HeaderEntry::Bin(&*header_sig));
    if let &Some(ref sig) = header_payload_sig {
        hdr.push(RPMSIGTAG_PGP, HeaderEntry::Bin(sig));
    }
    if let &Some(ref weak_digest) = header_payload_weak_digest {
        hdr.push(RPMSIGTAG_MD5, HeaderEntry::Bin(weak_digest));
    }
    let mut out_data = vec![0; magic_offset];
    out_data[..magic_offset].copy_from_slice(&main_header.lead());
    hdr.emit(&mut out_data).expect("writes to a vec never fail");
    let fixup = (out_data.len() + 7 & !7) - out_data.len();
    out_data.extend_from_slice(&[0u8; 7][..fixup]);
    #[cfg(debug_assertions)]
    rpm_parser::load_signature(&mut &out_data[magic_offset..], _allow_weak_hashes, _token).unwrap();
    dest.write_all(&out_data)?;
    dest.write_all(&main_header_bytes)
}

fn process_file(
    tx: &RpmTransactionSet,
    src: &std::ffi::OsStr,
    dst: &std::ffi::OsStr,
    allow_weak_hashes: AllowWeakHashes,
    allow_old_pkgs: bool,
    preserve_old_signature: bool,
    token: rpm_crypto::InitToken,
) -> Result<()> {
    let emit_header: &mut FnMut(
        &rpm_parser::VerifyResult,
        Option<&mut std::io::Write>,
    ) -> std::io::Result<()> = &mut |x, y| emit_header(x, y, allow_weak_hashes, token);
    let mut s = File::open(src)?;
    // Ignore the lead
    let _ = rpm_parser::read_lead(&mut s)?;
    // Read the signature header
    let mut sig_header = rpm_parser::load_signature(&mut s, allow_weak_hashes, token)?;
    let mut do_rename = true;
    let (parent_dir, mut dest, fname, tmp_path) = {
        let mut options = OpenOptions::new();
        let path = Path::new(dst);
        let (mut parent, fname) = match (path.parent(), path.file_name()) {
            (Some(p), Some(s)) => (p, s),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Cannot write to directory",
                ))
            }
        };
        if parent.as_os_str().is_empty() {
            parent = Path::new(OsStr::from_bytes(b"."))
        }
        let parent = options
            .mode(0o640)
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent)?;
        #[cfg_attr(target_os = "linux", allow(unused_mut))]
        let mut tmp_path: Option<CString> = None;
        unsafe {
            #[cfg(target_os = "linux")]
            let mut res = {
                static PATH: &[u8] = &*b".\0";
                libc::openat(
                    parent.as_raw_fd(),
                    PATH.as_ptr() as *const libc::c_char,
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_TMPFILE,
                    0o640,
                )
            };
            #[cfg(not(target_os = "linux"))]
            let mut res = {
                extern "C" {
                    fn getentropy(
                        ptr: *const std::os::raw::c_void,
                        size: std::os::raw::size_t,
                    ) -> std::os::raw::c_int;
                }
                let mut rand: u64 = 0;
                if getentropy(&mut rand as *mut u64 as *mut _, std::mem::size_of::<u64>()) != 0 {
                    panic!("randomness error");
                }
                let s = format!("tmpfile-{}.UNTRUSTED\0", rand);
                tmp_path = Some(CStr::from_bytes_with_nul(s.as_bytes()).unwrap().to_owned());
                let mut res = libc::openat(
                    parent.as_raw_fd(),
                    s.as_ptr() as *const libc::c_char,
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_EXCL | libc::O_CREAT,
                    0640,
                );
                res
            };
            let fname = fname.as_bytes();
            let c_fname = CString::new(fname).expect("NUL in command line banned");
            if res < 0 {
                match errno() {
                    // Special case for /dev/null
                    libc::ENOTSUP | libc::EPERM | libc::EACCES if fname == b"/dev/null" => {
                        res = libc::openat(
                            parent.as_raw_fd(),
                            c_fname.as_ptr() as *const std::os::raw::c_char,
                            libc::O_RDWR | libc::O_CLOEXEC,
                        );
                        do_rename = false;
                    }
                    _ => {}
                }
                if res < 0 {
                    let s = std::io::Error::last_os_error();
                    return Err(s);
                }
            }
            (parent, File::from_raw_fd(res), c_fname, tmp_path)
        }
    };
    let rpm_parser::VerifyResult { .. } = rpm_parser::verify_package(
        &mut s,
        &mut sig_header,
        &tx.keyring(),
        allow_old_pkgs,
        preserve_old_signature,
        token,
        Some(emit_header),
        Some(&mut dest),
    )
    .map_err(|e| {
        if cfg!(not(target_os = "linux")) {
            unsafe {
                let _ = libc::unlinkat(
                    parent_dir.as_raw_fd(),
                    tmp_path.as_ref().unwrap().as_ptr(),
                    0,
                );
            }
        };
        e
    })?;
    dest.flush()?;
    if !do_rename {
        Ok(())
    } else if if cfg!(target_os = "linux") {
        let proc_dir = format!("/proc/self/fd/{}\0", dest.as_raw_fd());
        let c = CString::new(fname.as_bytes()).expect("NUL forbidden");
        unsafe {
            loop {
                let i = libc::linkat(
                    libc::AT_FDCWD,
                    proc_dir.as_ptr() as *const _,
                    parent_dir.as_raw_fd(),
                    c.as_ptr() as *const _,
                    libc::AT_SYMLINK_FOLLOW,
                );
                if i != -1 || errno() != libc::EEXIST {
                    break i;
                }
                if libc::unlinkat(parent_dir.as_raw_fd(), c.as_ptr() as *const _, 0) != 0 {
                    break -1;
                }
            }
        }
    } else {
        unsafe {
            libc::renameat(
                parent_dir.as_raw_fd(),
                tmp_path.unwrap().as_ptr(),
                parent_dir.as_raw_fd(),
                fname.as_ptr(),
            )
        }
    } < 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn inner_main() -> i32 {
    let token = rpm_crypto::init();
    let mut args = std::env::args_os().into_iter();
    let mut allow_weak_hashes = AllowWeakHashes::No;
    let mut allow_old_pkgs = false;
    let mut preserve_old_signature = false;
    let _ = match args.next() {
        Some(s) => s,
        None => return usage(false),
    };
    for i in &mut args {
        match i.as_bytes() {
            b"--allow-weak-hashes" => allow_weak_hashes = AllowWeakHashes::Yes,
            b"--help" => return usage(true),
            b"--allow-old-pkgs" => allow_old_pkgs = true,
            b"--preserve-old-signature" => preserve_old_signature = true,
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
    match process_file(
        &tx,
        &src,
        &dst,
        allow_weak_hashes,
        allow_old_pkgs,
        preserve_old_signature,
        token,
    ) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error canonicalizing file: {}", e);
            1
        }
    }
}
