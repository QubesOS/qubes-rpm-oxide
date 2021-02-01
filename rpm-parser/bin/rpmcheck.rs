use std::fs::File;
use std::io::Result;
fn main() -> Result<()> {
    let mut args = std::env::args_os();
    if args.next().is_none() {
        return Ok(());
    };
    for i in args {
        let mut s = File::open(i)?;
        rpm_parser::RPMPackage::read(&mut s)?;
    }
    Ok(())
}
