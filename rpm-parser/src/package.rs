//! Routines for parsing entire RPM packages
//!
//! An RPM package consists of a lead, signature header, immutable header, and
//! payload.  The payload is an opaque compressed archive.

use crate::{
    header::{ImmutableHeader, SignatureHeader},
    load_immutable, load_signature, read_lead, RPMLead,
};
use std::io::{Read, Result};

/// An RPM package
pub struct RPMPackage {
    pub lead: RPMLead,
    pub signature: SignatureHeader,
    pub immutable: ImmutableHeader,
}

impl RPMPackage {
    /// Load a package from `r`
    pub fn read(r: &mut dyn Read) -> Result<Self> {
        let lead = read_lead(r)?;
        let signature = load_signature(r)?;
        let immutable = load_immutable(r)?;
        Ok(Self {
            lead,
            signature,
            immutable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_lua_rpm() {
        let mut s: &[u8] = include_bytes!("../../lua-5.4.2-1.fc33.x86_64.rpm");
        let RPMPackage {
            lead: _,
            signature,
            immutable,
        } = RPMPackage::read(&mut s).unwrap();
        let SignatureHeader {
            header: _,
            header_signature,
            header_payload_signature,
        } = signature;
        assert!(header_signature.is_some());
        assert!(header_payload_signature.is_some());
        let (mut ctx, digest) = immutable.payload_digest().unwrap();
        ctx.update(s);
        assert_eq!(ctx.finalize(true), digest);
    }
}
