#![feature(rustc_private)] // hack hack
#![feature(libc)]
#![cfg_attr(bare_trait_obj_deprecated, allow(bare_trait_objects))]
#![cfg_attr(
    ellipsis_inclusive_range_deprecated,
    allow(ellipsis_inclusive_range_patterns)
)]
#![cfg_attr(const_fn_unstable, feature(const_fn))]

#[cfg(any(
    not(any(const_fn_stable, const_fn_unstable)),
    not(any(bare_trait_obj_deprecated, bare_trait_obj_allowed)),
    not(any(ellipsis_inclusive_range_deprecated, ellipsis_inclusive_range_allowed)),
    not(any(try_from_stable, try_from_unstable))
))]
compile_error!("build script bug");

extern crate libc;
extern crate openpgp_parser;
extern crate rpm_crypto;
extern crate rpm_parser;
extern crate rpm_writer;

use openpgp_parser::AllowWeakHashes;
use rpm_crypto::transaction::RpmTransactionSet;
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::Write;
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

fn usage(success: bool) -> i32 {
    const USAGE: &'static str = "Usage: rpmcanon [OPTIONS] -- SOURCE DESTINATION\n\n\
                                 Options:\n\n\
                                 --help print this message\n\
                                 --preserve-old-signature Preserve and require the RPMv3 (header+payload) signature\n\
                                 --allow-weak-hashes allow packages signed with SHA-1 or SHA-224\n\
                                 --allow-old-pkgs allow packages that don’t have a payload digest in the main header\n\
                                 --dbpath=<path> set the RPM database path";
    if success {
        println!("{}", USAGE);
        0
    } else {
        eprintln!("{}", USAGE);
        1
    }
}

mod progress_reader {
    use std;
    pub enum ReportProgress {
        No,
        Yes,
    }
    use File;
    pub struct ProgressReportingReader {
        inner: File,
        do_report: Option<u64>,
    }
    impl ProgressReportingReader {
        pub fn new(inner: File, report: ReportProgress) -> Self {
            match report {
                ReportProgress::Yes => Self {
                    inner,
                    do_report: Some(0),
                },
                ReportProgress::No => Self {
                    inner,
                    do_report: None,
                },
            }
        }
    }
    impl std::io::Read for ProgressReportingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let bytes_read = self.inner.read(buffer)?;
            if let Some(ref mut bytes_so_far) = self.do_report {
                if bytes_read == 0 {
                    println!("{} bytes total", *bytes_so_far);
                } else {
                    let old_count = *bytes_so_far >> 20;
                    let new_count = *bytes_so_far + bytes_read as u64;
                    if new_count >> 20 != old_count {
                        println!("{} bytes so far", new_count)
                    }
                    *bytes_so_far = new_count;
                }
            }
            Ok(bytes_read)
        }
    }
}
use progress_reader::ReportProgress;

fn process_file(
    tx: &RpmTransactionSet,
    src: &std::ffi::OsStr,
    dst: &std::ffi::OsStr,
    allow_weak_hashes: AllowWeakHashes,
    allow_old_pkgs: bool,
    preserve_old_signature: bool,
    report_progress: ReportProgress,
    token: rpm_crypto::InitToken,
) -> std::io::Result<()> {
    let mut s = progress_reader::ProgressReportingReader::new(File::open(src)?, report_progress);
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
    rpm_writer::canonicalize_package(
        allow_old_pkgs,
        preserve_old_signature,
        token,
        &mut s,
        &mut dest,
        allow_weak_hashes,
        &tx.keyring(),
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
    let mut args = std::env::args_os().into_iter();
    let mut allow_weak_hashes = AllowWeakHashes::No;
    let mut allow_old_pkgs = false;
    let mut preserve_old_signature = false;
    let mut report_progress = ReportProgress::No;
    let _ = match args.next() {
        Some(s) => s,
        None => return usage(false),
    };
    let mut dbpath: Option<CString> = None;
    for i in &mut args {
        let bytes = i.as_bytes();
        match bytes {
            b"--allow-weak-hashes" => allow_weak_hashes = AllowWeakHashes::Yes,
            b"--help" => return usage(true),
            b"--allow-old-pkgs" => allow_old_pkgs = true,
            b"--preserve-old-signature" => preserve_old_signature = true,
            b"--report-progress" => report_progress = ReportProgress::Yes,
            b"--" => break,
            _ if bytes.starts_with(b"--dbpath=") && dbpath.is_none() => {
                dbpath = Some(CString::new(&bytes[9..]).expect("NUL in command line banned"))
            }
            _ => return usage(false),
        }
    }
    let token = if let Some(dbpath) = dbpath {
        rpm_crypto::init(Some(&*dbpath))
    } else {
        rpm_crypto::init(None)
    };
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
        report_progress,
        token,
    ) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error canonicalizing file: {}", e);
            1
        }
    }
}
