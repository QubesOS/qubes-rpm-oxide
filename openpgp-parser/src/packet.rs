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

/// The critical flag of a subpacket
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Critical {
    /// Subpacket is not critical
    No = 0,
    /// Subpacket is critical
    Yes = 0x80,
}

/// An OpenPGP packet
#[derive(Clone, Debug)]
pub struct Packet<'a> {
    tag: u8,
    buffer: Reader<'a>,
}

/// An OpenPGP subpacket
#[derive(Clone, Debug)]
pub struct Subpacket<'a> {
    tag: u8,
    buffer: Reader<'a>,
}

/// Get a series of `lenlen` big-endian bytes as a [`u32`].  Fails if `lenlen`
/// is larger than 4 **or** larger than `std::mem::size_of::<usize>()`.
/// Therefore, the return value will always be less than `usize::MAX`.
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

fn get_varlen_bytes<'a>(reader: &mut Reader<'a>) -> Result<Reader<'a>, Error> {
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
    if packet.tag() != 0 {
        Ok(Some(packet))
    } else {
        Err(Error::BadTag)
    }
}

impl<'a> Packet<'a> {
    /// Retrieves the packet’s tag.  Will always return non-zero.
    // this is a lie; it can return zero in next(), but then the packet
    // is immediately dropped.
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

impl<'a> Subpacket<'a> {
    /// Create a subpacket from the specified byte slice.
    ///
    /// Returns `Err` if the slice is not a single, properly-serialized
    /// subpacket.
    ///
    /// ```rust
    /// # use openpgp_parser::{buffer::Reader, packet::{Subpacket, Critical}};
    /// Subpacket::new(0x7F, Critical::Yes, Reader::empty()).unwrap();
    /// Subpacket::new(0x80, Critical::Yes, Reader::empty()).unwrap_err();
    /// ```
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(data);
        let tag = reader.byte()?;
        #[cfg(test)]
        eprintln!("Tag byte is 0b{:b}", tag);
        let buffer = get_varlen_bytes(&mut reader)?;
        match reader.is_empty() {
            true => Ok(Subpacket { tag, buffer }),
            false => Err(Error::TrailingJunk),
        }
    }

    /// Creates a subpacket from the specified byte slice, criticality, and tag.
    ///
    /// Succeeds if `tag` is less than `0x80`.  Otherwise fails.
    ///
    /// ```rust
    /// # use openpgp_parser::{buffer::Reader, packet::{Subpacket, Critical}, Error};
    /// let empty_reader = Reader::new(&[][..]);
    /// assert_eq!(
    ///     Subpacket::new(0x80, Critical::Yes, empty_reader.clone()).unwrap_err(),
    ///     Error::BadTag,
    /// );
    /// let critical = Subpacket::new(0x7F, Critical::Yes, empty_reader.clone()).unwrap();
    /// assert_eq!(critical.critical(), Critical::Yes);
    /// assert_eq!(critical.tag(), 0x7F);
    /// assert_eq!(critical.data(), empty_reader);
    /// let reader = Reader::new(&[20]);
    /// let not_critical = Subpacket::new(0x30, Critical::No, reader.clone()).unwrap();
    /// assert_eq!(not_critical.critical(), Critical::No);
    /// assert_eq!(not_critical.tag(), 0x30);
    /// assert_eq!(not_critical.data(), reader);
    /// ```
    pub fn new(tag: u8, critical: Critical, buffer: Reader<'a>) -> Result<Self, Error> {
        match tag > 0x7F {
            true => Err(Error::BadTag),
            false => Ok(Subpacket {
                tag: tag | critical as u8,
                buffer,
            }),
        }
    }

    /// Obtain the contents of a subpacket as a [`Reader`].
    pub fn contents(&self) -> Reader<'a> {
        self.buffer.clone()
    }

    /// Returns the length of the contents
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Read a subpacket from `reader`.  Subpackets are always new-format
    /// and may be critical.
    pub fn subpacket(reader: &mut Reader<'a>) -> Result<Option<Self>, Error> {
        if reader.is_empty() {
            return Ok(None);
        }
        let mut buffer = get_varlen_bytes(reader)?;
        let tag = buffer.byte()?;
        #[cfg(test)]
        eprintln!("Tag byte is {}", tag);
        Ok(Some(Subpacket { tag, buffer }))
    }

    /// Retrieves the packet’s tag
    ///
    /// ```rust
    /// # use openpgp_parser::{buffer::Reader, packet::{Subpacket, Critical}};
    /// let mut p = Subpacket::new(0x7F, Critical::Yes, Reader::new(&[][..])).unwrap();
    /// assert_eq!(p.tag(), 0x7F);
    /// ```
    pub fn tag(&self) -> u8 {
        self.tag & 0x7F
    }

    /// Retrieves whether the subpacket is critical.
    /// ```rust
    /// # use openpgp_parser::{buffer::Reader, packet::{Subpacket, Critical}};
    /// let mut p = Subpacket::new(0x7F, Critical::Yes, Reader::new(&[][..])).unwrap();
    /// assert_eq!(p.critical(), Critical::Yes);
    /// ```
    pub fn critical(&self) -> Critical {
        if self.tag & 0x80 == 0 {
            Critical::No
        } else {
            Critical::Yes
        }
    }

    /// Retrieves the data of a subpacket.
    pub fn data(&self) -> Reader<'a> {
        self.buffer.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subpacket() {
        let mut p = Subpacket {
            tag: 0x85,
            buffer: Reader::new(&[][..]),
        };
        assert!(p.critical() == Critical::Yes);
        assert!(p.tag() == 0x5);
        p.tag &= 0x7F;
        assert!(p.critical() == Critical::No);
        assert!(p.tag() == 0x5);
    }
}
