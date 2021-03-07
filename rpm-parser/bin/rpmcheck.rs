use openpgp_parser::AllowWeakHashes;
use std::fs::File;
use std::io::{copy, Error, ErrorKind, Result};
fn main() -> Result<()> {
    let mut args = std::env::args_os();
    if args.next().is_none() {
        return Ok(());
    };
    let token = rpm_crypto::init();
    for i in args {
        let mut s = File::open(i)?;
        let package = rpm_parser::RPMPackage::read(&mut s, AllowWeakHashes::No, token)?;
        package
            .signature
            .header_signature
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Package header is not signed"))?;
        let (mut ctx, digest) = package.immutable.payload_digest()?;
        copy(&mut s, &mut ctx)?;
        if ctx.finalize(true) != digest {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Payload digest failed to verify!",
            ));
        }
    }
    Ok(())
}
