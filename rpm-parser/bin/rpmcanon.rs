use rpm_parser::{RPMPackage, TagData, TagType, DigestCtx};
use std::fs::File;
use std::io::{copy, Error, ErrorKind, Read, Result, Seek, SeekFrom, Write};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        eprintln!("Usage: rpmcanon SOURCE DESTINATION");
        std::process::exit(1.into());
    }
    let mut s = File::open(&args[1])?;
    let mut dest = File::create(&args[2])?;
    let package = RPMPackage::read(&mut s)?;
    let untrusted_sig_body = package
        .signature
        .header_signature
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Package header is not signed"))?
        .1;
    let (mut ctx, digest) = package.immutable.payload_digest()?;
    copy(&mut s, &mut ctx)?;
    if ctx.finalize(true) != digest {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Payload digest failed to verify!",
        ));
    }
    assert!(!untrusted_sig_body.is_empty());
    let sig_len = untrusted_sig_body.len();
    assert!((sig_len as u64) < u32::MAX as u64);
    // 167 = 96 + 16 + 16 + 16 + 16 + 16 + 65 + 7
    const SHA256_HEX_LEN: usize = 65;
    let magic_offset = 96;
    let index_offset = magic_offset + 16;
    let sig_offset = index_offset + 16 * 3;
    let digest_offset = sig_offset + sig_len;
    let trailer_offset = digest_offset + SHA256_HEX_LEN;
    let end_trailer = trailer_offset + 16;
    let mut out_data = vec![0; (7 + end_trailer) & !7usize];
    s.seek(SeekFrom::Start(0))?;
    s.read_exact(&mut out_data[..magic_offset])?;
    let tags = &[
        TagData::new(0x8eade801, 0, 3, (end_trailer - sig_offset) as _),
        TagData::new(62, TagType::Bin as _, (trailer_offset - sig_offset) as _, 16),
        TagData::new(256 + 12, TagType::Bin as _, 0, sig_len as _),
        TagData::new(256 + 17, TagType::String as _, sig_len as _, 1),
    ];
    let trailer = &[TagData::new(62, TagType::Bin as _, (-48i32) as u32, 16)];
    let immutable_header = package.immutable.header;
    let immutable_magic = &[
        TagData::new(0x8eade801, 0, immutable_header.index.len() as _, immutable_header.data.len() as _),
    ];
    out_data[magic_offset..sig_offset].copy_from_slice(TagData::as_bytes(&*tags));
    out_data[sig_offset..digest_offset].copy_from_slice(&*untrusted_sig_body);
    let mut hdr_digest = DigestCtx::init(8).expect("SHA-256 is supported");
    hdr_digest.update(TagData::as_bytes(immutable_magic));
    hdr_digest.update(TagData::as_bytes(&immutable_header.index));
    hdr_digest.update(&*immutable_header.data);
    out_data[digest_offset..trailer_offset].copy_from_slice(&hdr_digest.finalize(true));
    out_data[trailer_offset..end_trailer].copy_from_slice(TagData::as_bytes(trailer));
    s.seek(SeekFrom::Current(
        (16 * (package.signature.header.index.len() + 1)
            + ((7 + package.signature.header.data.len()) & !7)) as _,
    ))?;
    dest.write_all(&out_data)?;
    copy(&mut s, &mut dest)?;
    Ok(())
}
