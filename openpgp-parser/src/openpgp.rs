//! A basic OpenPGP packet parser

use super::buffer::{EOFError, Reader};

/// The format of a packet
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum Format {
    /// Old format
    Old = 0,
    /// New format
    New = 0x40,
}

/// The critical flag of a subpacket
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum Critical {
    /// Subpacket is not critical
    No = 0,
    /// Subpacket is critical
    Yes = 0x80,
}

/// An OpenPGP packet
#[derive(Copy, Clone, Debug)]
pub struct Packet<'a> {
    tag: u8,
    buffer: &'a [u8],
}

/// An OpenPGP subpacket
#[derive(Copy, Clone, Debug)]
pub struct Subpacket<'a> {
    tag: u8,
    buffer: &'a [u8],
}

/// Errors that can occur during parsing
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// First bit of the first byte of a packet is zero
    PacketFirstBitZero,
    /// Length field is too long
    TooLong,
    /// Packet is truncated
    PrematureEOF,
    /// Indefinite-length old format packet detected.  These are not supported.
    IndefiniteLength,
    /// Partial-length new format packet detected.  These are not supported.
    PartialLength,
}

impl From<EOFError> for Error {
    fn from(EOFError: EOFError) -> Error {
        Error::PrematureEOF
    }
}

/// Get a series of `lenlen` big-endian bytes as a [`u32`].  Fails if `lenlen`
/// is larger than 4 **or** larger than `std::mem::size_of::<usize>()`.
pub fn get_be_u32(reader: &mut Reader, lenlen: u8) -> Result<u32, Error> {
    reader.read(|reader| {
        let mut len = 0u32;
        if lenlen > 4 || usize::from(lenlen) > core::mem::size_of::<usize>() {
            return Err(Error::TooLong);
        }
        for &i in reader.get(usize::from(lenlen))? {
            len = len << 8 | u32::from(i)
        }
        Ok(len)
    })
}

/// Reads `lenlen` bytes of data as a `u32` using [`Self::get_be_u32`], then
/// reads that number of bytes.  Returns [`Error::TooLong`] if `lenlen > 4`, or
/// [`Error::PrematureEOF`] if `Self` is too short.
pub fn get_length_bytes<'a>(reader: &mut Reader<'a>, lenlen: u8) -> Result<&'a [u8], Error> {
    reader.read(|reader| {
        // `as` is harmless, as `get_be_u32` already checks that its return
        // value fits in a `usize`
        let len = get_be_u32(reader, lenlen)? as usize;
        Ok(reader.get(len)?)
    })
}

fn get_varlen_bytes<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let keybyte: u8 = reader.byte()?;
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

/// Read a subpacket from `reader`.  Subpackets are always new-format
/// and may be critical.
pub fn subpacket<'a>(reader: &mut Reader<'a>) -> Result<Option<Subpacket<'a>>, Error> {
    let tag: u8 = match reader.maybe_byte() {
        Some(e) => e,
        None => return Ok(None),
    };
    Ok(Some(Subpacket { tag, buffer: get_varlen_bytes(reader)? }))
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
    Ok(Some(if tagbyte & 0x40 == 0 {
        // We deliberately do not support indefinite-length packets.
        // Just let `get_length_bytes` detect that (1u8 << 0b11) > 4 and bail out.
        let buffer = get_length_bytes(reader, 1u8 << (tagbyte & 0b11))?;
        Packet {
            tag: (0xF & (tagbyte >> 2)) | (tagbyte & 0b1100_0000),
            buffer,
        }
    } else {
        let buffer = get_varlen_bytes(reader)?;
        Packet {
            tag: tagbyte,
            buffer,
        }
    }))
}

impl<'a> Packet<'a> {
    /// Retrieves the packet’s tag
    pub fn tag(&self) -> u8 {
        self.tag & 0x3F
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

impl<'a> Subpacket<'a> {
    /// Retrieves the packet’s tag
    pub fn tag(&self) -> u8 {
        self.tag & 0x7F
    }

    /// Retrieves whether the subpacket is critical.
    pub fn critical(&self) -> Critical {
        if self.tag & 0x80 == 0 {
            Critical::No
        } else {
            Critical::Yes
        }
    }
}
