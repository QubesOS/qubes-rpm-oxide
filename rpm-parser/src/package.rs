//! Routines for parsing entire RPM packages
//!
//! An RPM package consists of a lead, signature header, immutable header, and
//! payload.  The payload is an opaque compressed archive.

use super::header::{ImmutableHeader, SignatureHeader};
use super::{load_immutable, load_signature, read_lead, RPMLead};
use openpgp_parser::AllowWeakHashes;
use rpm_crypto::InitToken;
use std;
use std::io::{Read, Result};

/// An RPM package
pub struct RPMPackage {
    pub lead: RPMLead,
    pub signature: SignatureHeader,
    pub immutable: ImmutableHeader,
}

include!("tables.rs");

impl RPMPackage {
    /// Load a package from `r`
    pub fn read(
        r: &mut dyn Read,
        allow_weak_hashes: AllowWeakHashes,
        token: InitToken,
    ) -> Result<Self> {
        let lead = read_lead(r)?;
        let signature = load_signature(r, allow_weak_hashes, token)?;
        let immutable = load_immutable(r, token)?;
        let (osnum, archnum) = (
            os_to_osnum(immutable.os.as_bytes()).unwrap_or(255),
            arch_to_archnum(immutable.arch.as_bytes()).unwrap_or(255),
        );
        if lead.osnum() != osnum {
            bad_data!(
                "Wrong OS number in lead (expected {}, found {})",
                osnum,
                lead.osnum(),
            )
        } else if lead.archnum() != archnum {
            bad_data!(
                "Wrong arch number in lead (expected {}, found {})",
                archnum,
                lead.archnum(),
            )
        }
        {
            let ImmutableHeader {
                ref name,
                ref version,
                ref release,
                epoch,
                ..
            } = immutable;
            let full_name = match epoch {
                Some(epoch) => format!("{}-{}:{}-{}", name, epoch, version, release),
                None => format!("{}-{}-{}", name, version, release),
            };
            let len_to_compare = full_name.len().min(65);
            debug_assert_eq!(lead.name()[65], 0);
            if full_name.as_bytes()[..len_to_compare] != lead.name()[..len_to_compare]
                || lead.name()[len_to_compare] != 0
            {
                bad_data!(
                    "name in lead {:?} does not match name in header {:?}",
                    std::str::from_utf8(&lead.name()[..len_to_compare])
                        .expect("package names are valid UTF-8"),
                    &full_name[..len_to_compare]
                )
            }
        }
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
        use rpm_crypto;
        let mut s: &[u8] = include_bytes!("../../data/lua-5.4.2-1.fc33.x86_64.rpm");
        let token = rpm_crypto::init(None);
        let RPMPackage {
            lead: _,
            signature,
            immutable,
        } = RPMPackage::read(&mut s, AllowWeakHashes::No, token).unwrap();
        let SignatureHeader {
            header: _,
            header_signature,
            header_payload_signature,
            header_payload_weak_digest: _,
            header_sha1_hash: _,
            header_sha256_hash: _,
        } = signature;
        assert!(header_signature.is_some());
        assert!(header_payload_signature.is_some());
        let (mut ctx, digest) = immutable.payload_digest().unwrap();
        ctx.update(s);
        assert_eq!(ctx.finalize(true), digest);
    }
}
