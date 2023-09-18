extern crate openpgp_parser;
use openpgp_parser::signature::{parse, SignatureType};
use openpgp_parser::AllowWeakHashes;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};
use std::time::{SystemTime, UNIX_EPOCH};
fn main() -> Result<()> {
    let mut args = std::env::args_os();
    if args.next().is_none() {
        return Ok(());
    };
    for i in args {
        let mut s = File::open(i)?;
        let mut buf_vec = Vec::new();
        s.read_to_end(&mut buf_vec)?;
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get time")
            .as_secs();
        parse(
            &mut buf_vec,
            time.try_into().unwrap(),
            AllowWeakHashes::No,
            SignatureType::Binary,
        )
        .or_else(|e| {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid signature: {:?}", e),
            ))
        })?;
    }
    Ok(())
}
