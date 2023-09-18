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

// RPM keyrings are synchronized by librpm
unsafe impl Send for RpmKeyring {}
unsafe impl Sync for RpmKeyring {}

#[link(name = "qubes-rpm-lib")]
extern "C" {
    fn qubes_rpm_rpmtsCreate() -> RpmTransactionSet;
    fn qubes_rpm_rpmKeyringLink(Keyring: *mut RpmKeyring_) -> RpmKeyring;
    fn qubes_rpm_rpmKeyringFree(Keyring: *mut RpmKeyring_) -> *mut RpmKeyring_;
    fn qubes_rpm_rpmtsLink(ts: *mut Rpmts) -> RpmTransactionSet;
    fn qubes_rpm_rpmtsFree(ts: *mut Rpmts) -> *mut Rpmts;
    fn qubes_rpm_rpmtsGetKeyring(ts: *mut Rpmts, autoload: c_int) -> *mut RpmKeyring_;
}

impl Drop for RpmKeyring {
    fn drop(&mut self) {
        unsafe { qubes_rpm_rpmKeyringFree(self.0) };
    }
}

impl Clone for RpmKeyring {
    fn clone(&self) -> Self {
        unsafe { qubes_rpm_rpmKeyringLink(self.0) }
    }
}

impl Drop for RpmTransactionSet {
    fn drop(&mut self) {
        let _mutex = grab_mutex(self.token());
        unsafe { qubes_rpm_rpmtsFree(self.0) };
    }
}

impl Clone for RpmTransactionSet {
    fn clone(&self) -> Self {
        let _mutex = grab_mutex(self.token());
        unsafe { qubes_rpm_rpmtsLink(self.0) }
    }
}

impl RpmTransactionSet {
    pub fn new(token: InitToken) -> Result<Self, ()> {
        let _mutex = grab_mutex(token);
        let v = unsafe { qubes_rpm_rpmtsCreate() };
        let keyring = RpmKeyring(unsafe { qubes_rpm_rpmtsGetKeyring(v.0, 1) });
        if keyring.0.is_null() {
            Err(())
        } else {
            Ok(v)
        }
    }

    pub fn keyring(&self) -> RpmKeyring {
        let ptr = unsafe { qubes_rpm_rpmtsGetKeyring(self.0, 0) };
        assert!(
            !ptr.is_null(),
            "keyring should have been autoloaded in new()"
        );
        RpmKeyring(ptr)
    }

    pub fn token(&self) -> InitToken {
        // SAFETY: creating this object requires an InitToken
        unsafe { InitToken::new() }
    }
}

impl RpmKeyring {
    pub fn validate_sig(&self, sig: Signature) -> Result<(), c_int> {
        #[link(name = "qubes-rpm-lib")]
        extern "C" {
            fn qubes_rpm_rpmKeyringVerifySig(
                keyring: *mut RpmKeyring_,
                sig: RawSignature,
                ctx: DigestCtx,
            ) -> c_int;
        }
        match unsafe { qubes_rpm_rpmKeyringVerifySig(self.0, sig.sig, sig.ctx) } {
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
