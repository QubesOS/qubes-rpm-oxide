use rpm_parser::{DigestCtx, TagData, TagType};
use std::convert::TryInto;
use std::fs::File;
use std::io::{copy, Error, ErrorKind, Read, Result, Seek, SeekFrom, Write};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        eprintln!("Usage: rpmcanon SOURCE DESTINATION");
        std::process::exit(1.into());
    }
    let token = rpm_parser::init();
    let tx = rpm_parser::RpmTransactionSet::new(token);
    let mut s = File::open(&args[1])?;
    let mut dest = File::create(&args[2])?;
    // Ignore the lead
    let _ = rpm_parser::read_lead(&mut s)?;
    // Read the signature header
    let sig_header = rpm_parser::load_signature(&mut s)?;
    let (mut signature, untrusted_sig_body) = sig_header
        .header_signature
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Package header is not signed"))?;

    let untrusted_sig_body = {
        openpgp_parser::packet::next(&mut openpgp_parser::buffer::Reader::new(
            &untrusted_sig_body,
        ))
        .expect("already parsed")
        .expect("already parsed")
        .serialize()
    };
    let mut prelude = [0u8; 16];

    // Read the prelude of the main header
    let (index_length, data_length) = {
        s.read_exact(&mut prelude)?;
        rpm_parser::parse_header_magic(&mut prelude)?
    };
    let mut main_header_bytes: Vec<u8> =
        vec![0u8; (16 * (index_length + 1) + data_length).try_into().unwrap()];
    main_header_bytes[..16].copy_from_slice(&prelude);
    s.read_exact(&mut main_header_bytes[16..])?;
    signature.update(&main_header_bytes);
    tx.keyring().validate_sig(signature).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            match e {
                2 => "Signature forged!",
                3 => "Key not trusted!",
                4 => "No key available!",
                _ => panic!("bad RPM retval"),
            },
        )
    })?;
    let main_header = rpm_parser::load_immutable(&mut &*main_header_bytes)?;
    let (mut ctx, digest) = main_header.payload_digest()?;
    let lead = main_header.lead();
    drop(main_header);
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
    out_data[..magic_offset].copy_from_slice(&lead);
    let tags = &[
        TagData::new(0x8eade801, 0, 3, (end_trailer - sig_offset) as _),
        TagData::new(
            62,
            TagType::Bin as _,
            (trailer_offset - sig_offset) as _,
            16,
        ),
        TagData::new(256 + 12, TagType::Bin as _, 0, sig_len as _),
        TagData::new(256 + 17, TagType::String as _, sig_len as _, 1),
    ];
    let trailer = &[TagData::new(62, TagType::Bin as _, (-48i32) as u32, 16)];
    out_data[magic_offset..sig_offset].copy_from_slice(TagData::as_bytes(&*tags));
    out_data[sig_offset..digest_offset].copy_from_slice(&*untrusted_sig_body);
    let mut hdr_digest = DigestCtx::init(8).expect("SHA-256 is supported");
    hdr_digest.update(&main_header_bytes);
    out_data[digest_offset..trailer_offset].copy_from_slice(&hdr_digest.finalize(true));
    out_data[trailer_offset..end_trailer].copy_from_slice(TagData::as_bytes(trailer));
    dest.write_all(&out_data)?;
    dest.write_all(&main_header_bytes)?;
    s.seek(SeekFrom::Start(
        (96 + 16
            + 16 * sig_header.header.index.len()
            + ((7 + sig_header.header.data.len()) & !7)
            + main_header_bytes.len()) as _,
    ))?;
    copy(&mut s, &mut dest)?;
    Ok(())
}
