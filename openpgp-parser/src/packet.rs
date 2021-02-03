//! Utility functions for parsing OpenPGP packets

use super::{buffer::Reader, Error};

/// The format of a packet
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Format {
    /// Old format
    Old = 0,
    /// New format
    New = 0x40,
}

/// An OpenPGP packet
#[derive(Clone, Debug)]
pub struct Packet<'a> {
    tag: u8,
    buffer: Reader<'a>,
}

/// Get a series of `lenlen` big-endian bytes as a [`u32`].  Fails if `lenlen`
/// is larger than 4 **or** larger than `std::mem::size_of::<usize>()`.
/// Therefore, the return value will always be less than `usize::MAX`.
///
/// ```rust
/// # use openpgp_parser::{packet::get_be_u32, buffer::Reader};
/// let mut reader = Reader::new(&[1, 2, 3, 4, 5]);
/// assert!(get_be_u32(&mut reader, 5).is_err());
/// assert_eq!(get_be_u32(&mut reader, 3).unwrap(), 0x10203);
/// assert!(get_be_u32(&mut reader, 3).is_err());
/// assert_eq!(get_be_u32(&mut reader, 1).unwrap(), 4);
/// assert_eq!(reader.len(), 1);
/// assert_eq!(reader.byte().unwrap(), 0x5);
/// ```
pub fn get_be_u32(reader: &mut Reader, lenlen: u8) -> Result<u32, Error> {
    reader.read(|reader| {
        let mut len = 0u32;
        if lenlen > 4 || usize::from(lenlen) > core::mem::size_of::<usize>() {
            return Err(Error::TooLong);
        }
        for &i in reader.get(usize::from(lenlen))?.as_untrusted_slice() {
            len = len << 8 | u32::from(i)
        }
        Ok(len)
    })
}

/// Reads `lenlen` bytes of data as a `u32` using [`Self::get_be_u32`], then
/// reads that number of bytes.  Returns [`Error::TooLong`] if `lenlen > 4`, or
/// [`Error::PrematureEOF`] if `Self` is too short.
pub fn get_length_bytes<'a>(reader: &mut Reader<'a>, lenlen: u8) -> Result<Reader<'a>, Error> {
    reader.read(|reader| {
        // `as` is harmless, as `get_be_u32` already checks that its return
        // value fits in a `usize`
        let len = get_be_u32(reader, lenlen)? as usize;
        Ok(reader.get(len)?)
    })
}

pub(crate) fn get_varlen_bytes<'a>(reader: &mut Reader<'a>) -> Result<Reader<'a>, Error> {
    let keybyte: u8 = reader.byte()?;
    #[cfg(test)]
    eprintln!("Keybyte is {}, reader length is {}", keybyte, reader.len());
    Ok(match keybyte {
        0..=191 => reader.get(keybyte.into())?,
        192..=223 => {
            let len = ((usize::from(keybyte) - 192) << 8) + usize::from(reader.byte()?) + 192;
            reader.get(len)?
        }
        // Partial lengths are deliberately unsupported, as we don’t handle PGP signed and/or
        // encrypted data ourselves.
        224..=254 => return Err(Error::PartialLength),
        255 => get_length_bytes(reader, 4)?,
    })
}

/// Read a packet from `reader`.  Returns:
///
/// - `Ok(Some(packet))` if a packet is read
/// - `Ok(None)` if the reader is empty.
/// - `Err` if an error occurred.
pub fn next<'a>(reader: &mut Reader<'a>) -> Result<Option<Packet<'a>>, Error> {
    let tagbyte: u8 = match reader.maybe_byte() {
        Some(e) if e & 0x80 == 0 => return Err(Error::PacketFirstBitZero),
        Some(e) => e,
        None => return Ok(None),
    };
    #[cfg(test)]
    eprintln!("Tag byte is 0b{:b}", tagbyte);
    let packet = if tagbyte & 0x40 == 0 {
        // We deliberately do not support indefinite-length packets.
        // Just let `get_length_bytes` detect that (1u8 << 0b11) > 4 and bail out.
        let buffer = get_length_bytes(reader, 1u8 << (tagbyte & 0b11))?;
        Packet {
            tag: 0xF & (tagbyte >> 2),
            buffer,
        }
    } else {
        let buffer = get_varlen_bytes(reader)?;
        Packet {
            tag: tagbyte & 0x7F,
            buffer,
        }
    };
    if packet.tag & 0x3F != 0 {
        Ok(Some(packet))
    } else {
        Err(Error::BadTag)
    }
}

impl<'a> Packet<'a> {
    /// Retrieves the packet’s tag.  Will always return non-zero.
    pub fn tag(&self) -> u8 {
        self.tag & 0x3F
    }

    /// Retrieves the packet’s contents as a `Reader`.
    pub fn contents(&self) -> Reader<'a> {
        self.buffer.clone()
    }

    /// Retrieves the packet’s format
    pub fn format(&self) -> Format {
        if self.tag & 0x40 == 0 {
            Format::Old
        } else {
            Format::New
        }
    }
}
