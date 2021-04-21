//! Utility functions for parsing OpenPGP packets

use super::{Error, Reader};

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
    buffer: &'a [u8],
}

pub(crate) fn get_varlen_bytes<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let keybyte: u8 = reader.byte()?;
    #[cfg(test)]
    eprintln!("Keybyte is {}, reader length is {}", keybyte, reader.len());
    let len: usize = match keybyte {
        0...191 => keybyte.into(),
        192...223 => ((usize::from(keybyte) - 192) << 8) + usize::from(reader.byte()?) + 192,
        255 => reader.be_u32()? as _,
        // Partial lengths are deliberately unsupported, as we don’t handle PGP signed and/or
        // encrypted data ourselves.
        _ => return Err(Error::PartialLength),
    };
    Ok(reader.get_bytes(len)?)
}

/// Read a packet from `reader`.  Returns:
///
/// - `Ok(Some(packet))` if a packet is read
/// - `Ok(None)` if the reader is empty.
/// - `Err` if an error occurred, such as trailing junk.
pub fn next<'a>(reader: &mut Reader<'a>) -> Result<Option<Packet<'a>>, Error> {
    let tagbyte: u8 = match reader.maybe_byte() {
        Some(e) if e & 0x80 == 0 => return Err(Error::PacketFirstBitZero),
        Some(e) => e,
        None => return Ok(None),
    };
    #[cfg(test)]
    eprintln!("Tag byte is 0b{:b}", tagbyte);
    let packet = if tagbyte & 0x40 == 0 {
        let lenlen = 1u8 << (tagbyte & 0b11);
        // We deliberately do not support indefinite-length packets.
        if lenlen > 4 {
            return Err(Error::PartialLength);
        }
        let mut len = 0usize;
        for &i in reader.get_bytes(usize::from(lenlen))? {
            len = len << 8 | usize::from(i)
        }
        Packet {
            tag: 0xF & (tagbyte >> 2),
            buffer: reader.get_bytes(len)?,
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

    /// Retrieves the packet’s contents as a slice.
    pub fn contents(&self) -> &'a [u8] {
        self.buffer
    }

    /// Retrieves the packet’s format
    pub fn format(&self) -> Format {
        if self.tag & 0x40 == 0 {
            Format::Old
        } else {
            Format::New
        }
    }

    /// Wraps the packet in OpenPGP encapsulation
    #[cfg(feature = "alloc")]
    pub fn serialize(&self) -> Vec<u8> {
        let len = self.buffer.len();
        assert!(u64::from(u32::max_value()) >= len as u64);
        if self.tag >= 16 {
            let tag_byte = self.tag | 0b1100_0000u8;
            match len {
                0...191 => {
                    // 1-byte
                    let mut v = Vec::with_capacity(2 + len);
                    v.push(tag_byte);
                    v.push(len as u8);
                    v.extend_from_slice(self.buffer);
                    v
                }
                192...8383 => {
                    // 2-byte
                    let mut v = Vec::with_capacity(3 + len);
                    let len = len - 192;
                    v.push(tag_byte);
                    v.push((len >> 8) as u8 + 192);
                    v.push(len as u8);
                    v.extend_from_slice(self.buffer);
                    v
                }
                _ => {
                    // 5-byte
                    let mut v = Vec::with_capacity(6 + len);
                    v.push(tag_byte);
                    v.extend_from_slice(&[
                        (len >> 24) as u8,
                        (len >> 16) as u8,
                        (len >> 8) as u8,
                        len as u8,
                    ]);
                    v.extend_from_slice(self.buffer);
                    v
                }
            }
        } else {
            let tag_byte = self.tag << 2 | 0b1000_0000u8;
            match len {
                0...0xFF => {
                    // 1-byte
                    let mut v = Vec::with_capacity(2 + len);
                    v.push(tag_byte | 0b00);
                    v.push(len as u8);
                    v.extend_from_slice(self.buffer);
                    v
                }
                0x100...0xFFFF => {
                    // 2-byte
                    let mut v = Vec::with_capacity(3 + len);
                    v.push(tag_byte | 0b01);
                    v.push((len >> 8) as u8);
                    v.push(len as u8);
                    v.extend_from_slice(self.buffer);
                    v
                }
                _ => {
                    // 5-byte
                    let mut v = Vec::with_capacity(5 + len);
                    v.push(tag_byte | 0b10);
                    v.extend_from_slice(&[
                        (len >> 24) as u8,
                        (len >> 16) as u8,
                        (len >> 8) as u8,
                        len as u8,
                    ]);
                    v.extend_from_slice(self.buffer);
                    v
                }
            }
        }
    }
}
