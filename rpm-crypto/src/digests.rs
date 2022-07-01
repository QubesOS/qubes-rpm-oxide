use openpgp_parser::AllowWeakHashes;
use std;
use std::io::{Result as IResult, Write};
use std::os::raw::{c_int, c_void};
use std::ptr;

#[repr(C)]
struct ExternDigestCtx(u8);

#[repr(C)]
pub struct DigestCtx(*mut ExternDigestCtx);

pub fn rpm_hash_len(alg: i32) -> usize {
    // SAFETY: this code is called correctly (and has 100% input coverage in the testsuite)
    unsafe { rpmDigestLength(alg) }
}

#[link(name = "c")]
extern "C" {
    fn free(ptr: *mut c_void);
}

#[link(name = ":librpmio.so.9")]
extern "C" {
    fn rpmDigestLength(tag: c_int) -> usize;
    fn rpmDigestDup(s: *mut ExternDigestCtx) -> DigestCtx;
    fn rpmDigestInit(hash_algo: c_int, flags: u32) -> DigestCtx;
    fn rpmDigestUpdate(s: *mut ExternDigestCtx, data: *const c_void, len: usize) -> c_int;
    fn rpmDigestFinal(
        ctx: *mut ExternDigestCtx,
        datap: Option<&mut *mut c_void>,
        lenp: Option<&mut usize>,
        asAscii: c_int,
    ) -> c_int;
}

impl Drop for DigestCtx {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a pointer to an RPM digest context.
        unsafe { rpmDigestFinal(self.0, None, None, 0) };
    }
}

impl Clone for DigestCtx {
    fn clone(&self) -> Self {
        // SAFETY: `self.0` is a pointer to an RPM digest context.
        unsafe { rpmDigestDup(self.0) }
    }
}

impl Write for DigestCtx {
    fn write(&mut self, buf: &[u8]) -> IResult<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IResult<()> {
        Ok(())
    }
}

impl DigestCtx {
    /// Initialize an RPM digest context
    pub fn init(
        algorithm: u8,
        allow_weak_hashes: AllowWeakHashes,
        _: super::InitToken,
    ) -> Result<DigestCtx, ()> {
        use openpgp_parser::signature::check_hash_algorithm;
        let len = check_hash_algorithm(algorithm.into(), allow_weak_hashes).map_err(drop)?;
        if rpm_hash_len(algorithm as _) != len as _ {
            return Err(());
        }
        // SAFETY: `rpmDigestInit` is safe for all inputs.
        let raw_p = unsafe { rpmDigestInit(algorithm.into(), 0) };
        assert!(!raw_p.0.is_null());
        Ok(raw_p)
    }

    pub fn update(&mut self, buf: &[u8]) {
        // SAFETY: `self.0` is a pointer to an RPM digest context, and
        // `buf.as_ptr()` points to `buf.len()` bytes of valid memory.
        unsafe { assert_eq!(rpmDigestUpdate(self.0, buf.as_ptr() as _, buf.len()), 0) }
    }

    pub fn finalize(self, ascii: bool) -> Vec<u8> {
        let mut p = ptr::null_mut();
        let this = self.0;
        // avoid double-free
        std::mem::forget(self);
        let mut len = 0;
        unsafe {
            assert_eq!(
                // SAFETY: we just forgot `self`, so the destructor will not
                // free the memory.
                rpmDigestFinal(this, Some(&mut p), Some(&mut len), ascii as _),
                0
            );
            assert!(!p.is_null());
            assert_eq!(len & 1, ascii as _);
            let mut retval: Vec<u8> = Vec::with_capacity(len);
            // SAFETY: both `p` and `retval.as_mut_ptr()` are freshly allocated heap pointers.
            ptr::copy_nonoverlapping(p as *const u8, retval.as_mut_ptr(), len);
            // SAFETY: we just initialized the vector.
            retval.set_len(len);
            // SAFETY: rpmDigestFinal() allocates the memory with `malloc`
            free(p);
            retval
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_rpm_supports_hashes() {
        use openpgp_parser::signature::check_hash_algorithm;
        for &i in &[8, 9, 10] {
            assert_eq!(
                super::rpm_hash_len(i),
                check_hash_algorithm(i, AllowWeakHashes::No).unwrap() as usize
            );
        }
    }
    #[test]
    fn check_rpm_crypto() {
        for &i in &[8, 9, 10] {
            let mut s = DigestCtx::init(i, AllowWeakHashes::No, super::super::init(None)).unwrap();
            println!("Initialized RPM crypto context");
            s.update(b"this is a test!");
            println!("Finalizing");
            let hex = s.clone().finalize(true);
            let len = hex.len();
            assert!(len & 1 == 1);
            assert_eq!(hex[len - 1], 0);
            println!(
                "Hex version: {}",
                std::str::from_utf8(&hex[..len - 1]).unwrap()
            );
            println!("{:?}", s.finalize(false))
        }
    }
    #[test]
    #[ignore]
    fn rpm_hash_len() {
        for i in i32::min_value()..i32::max_value() {
            let r = super::rpm_hash_len(i);
            assert!(r == usize::max_value() || r < 100);
        }
    }
}
