use super::{grab_mutex, DigestCtx, InitToken, RawSignature, Signature};
use std::os::raw::c_int;

#[repr(C)]
struct Rpmts(u8);
#[repr(C)]
struct RpmKeyring_(u8);

#[repr(C)]
pub struct RpmTransactionSet(*mut Rpmts);

#[repr(C)]
pub struct RpmKeyring(*mut RpmKeyring_);

#[link(name = ":librpm.so.9")]
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
        let _mutex = grab_mutex(self.token());
        unsafe { rpmKeyringFree(self.0) };
    }
}

impl Clone for RpmKeyring {
    fn clone(&self) -> Self {
        let _mutex = grab_mutex(self.token());
        unsafe { rpmKeyringLink(self.0) }
    }
}

impl Drop for RpmTransactionSet {
    fn drop(&mut self) {
        let _mutex = grab_mutex(self.token());
        unsafe { rpmtsFree(self.0) };
    }
}

impl Clone for RpmTransactionSet {
    fn clone(&self) -> Self {
        let _mutex = grab_mutex(self.token());
        unsafe { rpmtsLink(self.0) }
    }
}

impl RpmTransactionSet {
    pub fn new(token: InitToken) -> Self {
        let _mutex = grab_mutex(token);
        unsafe { rpmtsCreate() }
    }

    pub fn keyring(&self) -> RpmKeyring {
        let _mutex = grab_mutex(self.token());
        let ptr = unsafe { rpmtsGetKeyring(self.0, 1) };
        assert!(!ptr.is_null(), "keyring should have been autoloaded");
        RpmKeyring(ptr)
    }

    pub fn token(&self) -> InitToken {
        // SAFETY: creating this object requires an InitToken
        unsafe { InitToken::new() }
    }
}

impl RpmKeyring {
    pub fn validate_sig(&self, sig: Signature) -> Result<(), c_int> {
        let _mutex = grab_mutex(self.token());
        #[link(name = ":librpm.so.9")]
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

    pub fn token(&self) -> InitToken {
        // SAFETY: creating this object requires an InitToken (via
        // RpmTransactionSet)
        unsafe { InitToken::new() }
    }
}
