use super::InitToken;
use openpgp_parser::{signature, AllowWeakHashes, Error};
use std;
use std::os::raw::{c_int, c_uint};
enum RpmPgpDigParams {}

#[repr(C)]
pub struct Signature(*mut RpmPgpDigParams);

impl Signature {
    pub fn parse(
        untrusted_buffer: &[u8],
        time: u32,
        allow_weak_hashes: AllowWeakHashes,
        _: InitToken,
    ) -> Result<Self, Error> {
        super::init();
        // Check that the signature is valid
        let sig_info = signature::parse(untrusted_buffer, time, allow_weak_hashes)?;
        // We can now pass the buffer to RPM, since it is a valid signature
        let slice = untrusted_buffer;
        let mut params = Signature(std::ptr::null_mut());
        let r = unsafe { pgpPrtParams(slice.as_ptr(), slice.len(), 2, &mut params) };
        assert!(r == 0, "we accepted a signature RPM rejected");
        assert!(!params.0.is_null());
        assert_eq!(params.hash_algorithm(), sig_info.hash_alg);
        assert_eq!(params.public_key_algorithm(), sig_info.pkey_alg);
        Ok(params)
    }

    /// Retrieve the hash algorithm of the signature
    pub fn hash_algorithm(&self) -> u8 {
        let alg = unsafe { pgpDigParamsAlgo(self.0, 9) };
        assert!(alg <= 255, "invalid hash algorithm not rejected earlier?");
        alg as _
    }

    /// Retrieve the public key algorithm of the signature
    pub fn public_key_algorithm(&self) -> u8 {
        (unsafe { pgpDigParamsAlgo(self.0, 6) }) as _
    }
}

impl Drop for Signature {
    fn drop(&mut self) {
        if !self.0.is_null() {
            self.0 = unsafe { pgpDigParamsFree(self.0) }
        }
    }
}

#[link(name = "rpmio")]
extern "C" {
    fn pgpPrtParams(pkts: *const u8, pktlen: usize, pkttype: c_uint, ret: &mut Signature) -> c_int;
    fn pgpDigParamsFree(digp: *mut RpmPgpDigParams) -> *mut RpmPgpDigParams;
    fn pgpDigParamsAlgo(digp: *const RpmPgpDigParams, algotype: c_uint) -> c_uint;
}
