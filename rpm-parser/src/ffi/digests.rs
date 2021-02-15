use openpgp_parser::AllowWeakHashes;
use std::os::raw::{c_int, c_void};
use std::ptr;

enum ExternDigestCtx {}
#[repr(transparent)]
pub struct DigestCtx(*mut ExternDigestCtx);

#[link(name = "c")]
extern "C" {
    fn free(ptr: *mut c_void);
}

#[link(name = "rpmio")]
extern "C" {
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
        unsafe { rpmDigestFinal(self.0, None, None, 0) };
    }
}

impl Clone for DigestCtx {
    fn clone(&self) -> Self {
        unsafe { rpmDigestDup(self.0) }
    }
}

impl std::io::Write for DigestCtx {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DigestCtx {
    /// Initialize an RPM digest context
    pub fn init(
        algorithm: u8,
        allow_sha1_sha224: AllowWeakHashes,
        _: super::InitToken,
    ) -> Result<DigestCtx, ()> {
        use openpgp_parser::signature::check_hash_algorithm;
        super::init();
        let len = check_hash_algorithm(algorithm.into(), allow_sha1_sha224).map_err(drop)?;
        #[cfg(test)]
        eprintln!("Hash algorithm {} accepted by us", algorithm);
        if super::rpm_hash_len(algorithm.into()) != len.into() {
            return Err(());
        }
        #[cfg(test)]
        eprintln!("Hash algorithm {} accepted by librpm", algorithm);
        let raw_p = unsafe { rpmDigestInit(algorithm.into(), 0) };
        assert!(!raw_p.0.is_null());
        Ok(raw_p)
    }

    pub fn update(&mut self, buf: &[u8]) {
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
                rpmDigestFinal(this, Some(&mut p), Some(&mut len), ascii as _),
                0
            );
            let mut retval: Vec<u8> = Vec::with_capacity(len);
            ptr::copy_nonoverlapping(p as *const u8, retval.as_mut_ptr(), len);
            retval.set_len(len);
            free(p);
            retval
        }
    }
}
