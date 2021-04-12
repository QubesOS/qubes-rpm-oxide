use super::{DigestCtx, InitToken, RawSignature, Signature};
use std::os::raw::c_int;

enum Rpmts {}
enum RpmKeyring_ {}
#[repr(C)]
pub struct RpmTransactionSet(*mut Rpmts);

#[repr(C)]
pub struct RpmKeyring(*mut RpmKeyring_);

#[link(name = "rpm")]
extern "C" {
    fn rpmtsCreate() -> RpmTransactionSet;
    fn rpmKeyringLink(Keyring: *mut RpmKeyring_) -> RpmKeyring;
    fn rpmKeyringFree(Keyring: *mut RpmKeyring_) -> *mut RpmKeyring_;
    fn rpmtsLink(ts: *mut Rpmts) -> RpmTransactionSet;
    fn rpmtsFree(ts: *mut Rpmts) -> *mut Rpmts;
    fn rpmtsGetKeyring(ts: *mut Rpmts, autoload: c_int) -> *mut RpmKeyring_;
}

impl Drop for RpmKeyring {
    fn drop(&mut self) {
        unsafe { rpmKeyringFree(self.0) };
    }
}

impl Clone for RpmKeyring {
    fn clone(&self) -> Self {
        unsafe { rpmKeyringLink(self.0) }
    }
}

impl Drop for RpmTransactionSet {
    fn drop(&mut self) {
        unsafe { rpmtsFree(self.0) };
    }
}

impl Clone for RpmTransactionSet {
    fn clone(&self) -> Self {
        unsafe { rpmtsLink(self.0) }
    }
}

impl RpmTransactionSet {
    pub fn new(_: InitToken) -> Self {
        unsafe { rpmtsCreate() }
    }

    pub fn keyring(&self) -> RpmKeyring {
        let ptr = unsafe { rpmtsGetKeyring(self.0, 1) };
        assert!(!ptr.is_null(), "keyring should have been autoloaded");
        RpmKeyring(ptr)
    }
}

impl RpmKeyring {
    pub fn validate_sig(&self, sig: Signature) -> Result<(), c_int> {
        #[link(name = "rpm")]
        extern "C" {
            fn rpmKeyringVerifySig(
                keyring: *mut RpmKeyring_,
                sig: RawSignature,
                ctx: DigestCtx,
            ) -> c_int;
        }
        match unsafe { rpmKeyringVerifySig(self.0, sig.sig, sig.ctx) } {
            0 => Ok(()),
            e => Err(e),
        }
    }
}
