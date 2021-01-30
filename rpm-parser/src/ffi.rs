//! FFI code

pub use signatures::Signature;
mod signatures {
    use openpgp_parser::{buffer::Reader, packet_types::read_signature, Error};
    use std::os::raw::{c_int, c_uint};
    enum RpmPgpDigParams {}

    #[repr(transparent)]
    pub struct Signature(*mut RpmPgpDigParams);

    impl Signature {
        /// Parse an OpenPGP signature.  The signature is validated before being passed
        /// to RPM.
        pub fn parse(buffer: Reader, time: u32) -> Result<Self, Error> {
            let mut cp = buffer.clone();
            // Check that the signature is valid
            read_signature(&mut cp, time)?;
            // We can now pass the buffer to RPM, since it is a valid signature
            let slice = buffer.as_untrusted_slice();
            let mut params = Signature(std::ptr::null_mut());
            let r = unsafe { pgpPrtParams(slice.as_ptr(), slice.len(), 2, &mut params) };
            assert!(r == 0, "we accepted a signature RPM rejected");
            assert!(!params.0.is_null());
            Ok(params)
        }

        /// Retrieve the hash algorithm of the signature
        pub fn hash_algorithm(&self) -> c_uint {
            unsafe { pgpDigParamsAlgo(self.0, 9) }
        }

        /// Retrieve the public key algorithm of the signature
        pub fn public_key_algorithm(&self) -> c_uint {
            unsafe { pgpDigParamsAlgo(self.0, 6) }
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
        fn pgpPrtParams(
            pkts: *const u8,
            pktlen: usize,
            pkttype: c_uint,
            ret: &mut Signature,
        ) -> c_int;
        fn pgpDigParamsFree(digp: *mut RpmPgpDigParams) -> *mut RpmPgpDigParams;
        fn pgpDigParamsAlgo(digp: *const RpmPgpDigParams, algotype: c_uint) -> c_uint;
    }
}

#[link(name = "rpm")]
extern "C" {
    fn rpmTagGetType(tag: std::os::raw::c_int) -> std::os::raw::c_int;
}

#[link(name = "rpmio")]
extern "C" {
    fn rpmDigestLength(tag: std::os::raw::c_int) -> usize;
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TagType {
    Char = 1,
    Int8 = 2,
    Int16 = 3,
    Int32 = 4,
    Int64 = 5,
    String = 6,
    Bin = 7,
    StringArray = 8,
    I18NString = 9,
}

pub fn rpm_hash_len(alg: i32) -> usize {
    unsafe { rpmDigestLength(alg) }
}

pub fn tag_type(tag: u32) -> Option<(TagType, bool)> {
    if tag > 0x7FFF {
        return None;
    }
    let ty = unsafe { rpmTagGetType(tag as _) };
    let is_array = match ty as u32 & 0xffff_0000 {
        0x10000 => false,
        0x20000 => true,
        // This should probably be a panic, but RPM does define
        // RPM_MAPPING_RETURN_TYPE, so just fail.
        _ => return None,
    };
    Some((
        match ty & 0xffff {
            0 => return None,
            1 => TagType::Char,
            2 => TagType::Int8,
            3 => TagType::Int16,
            4 => TagType::Int32,
            5 => TagType::Int64,
            6 => TagType::String,
            7 => TagType::Bin,
            8 => TagType::StringArray,
            9 => TagType::I18NString,
            _ => unreachable!("invalid return from rpmTagGetTagType()"),
        },
        is_array,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_rpm_supports_hashes() {
        use openpgp_parser::packet_types::check_hash_algorithm;
        for &i in &[8, 9, 10] {
            assert_eq!(
                unsafe { rpmDigestLength(i) },
                check_hash_algorithm(i).unwrap().into()
            );
        }
    }
}
