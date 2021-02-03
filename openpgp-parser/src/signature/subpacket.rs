use super::{Error, Reader};
use crate::packet::get_varlen_bytes;

/// OpenPGP signature subpackets
///
/// OpenPGP v4 signatures can have subpackets, which provide additional
/// information about the signature.  Subpackets may be hashed or unhashed.
/// Only hashed subpackets are protected by the signature.
#[derive(Clone, Debug)]
pub struct Subpacket<'a> {
    tag: u8,
    buffer: Reader<'a>,
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

impl<'a> Subpacket<'a> {
    /// Create a subpacket from the specified byte slice.
    ///
    /// Returns `Err` if the slice is not a single, properly-serialized
    /// subpacket.
    ///
    /// ```rust
    /// # use openpgp_parser::{buffer::Reader, signature::{Subpacket, Critical}};
    /// Subpacket::new(0x7F, Critical::Yes, Reader::empty()).unwrap();
    /// Subpacket::new(0x80, Critical::Yes, Reader::empty()).unwrap_err();
    /// ```
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(data);
        let tag = reader.byte()?;
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
    /// # use openpgp_parser::{buffer::Reader, signature::{Subpacket, Critical}, Error};
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
    pub fn subpacket(reader: &mut Reader<'a>) -> Result<Self, Error> {
        let mut buffer = get_varlen_bytes(reader)?;
        let tag = buffer.byte()?;
        Ok(Subpacket { tag, buffer })
    }

    /// Retrieves the packet’s tag
    ///
    /// ```rust
    /// # use openpgp_parser::{buffer::Reader, signature::{Subpacket, Critical}};
    /// let mut p = Subpacket::new(0x7F, Critical::Yes, Reader::new(&[][..])).unwrap();
    /// assert_eq!(p.tag(), 0x7F);
    /// ```
    pub fn tag(&self) -> u8 {
        self.tag & 0x7F
    }

    /// Retrieves whether the subpacket is critical.
    /// ```rust
    /// # use openpgp_parser::{buffer::Reader, signature::{Subpacket, Critical}};
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

/// An iterator over OpenPGP subpackets
#[derive(Clone, Debug)]
pub struct SubpacketIterator<'a> {
    buffer: Reader<'a>,
}

impl<'a> SubpacketIterator<'a> {
    /// Reads a big-endian 16-bit number, followed by that many bytes of subpackets.
    /// This function checks that the subpackets can be iterated over before
    /// returning.
    pub fn read_u16_prefixed(buffer: &mut Reader<'a>) -> Result<Self, Error> {
        let buffer = buffer.read::<_, Error, _>(|buffer| {
            let len = buffer.be_u16()?;
            let buffer = buffer.get(len.into())?;
            let mut dup_buffer = buffer.clone();
            while !dup_buffer.is_empty() {
                let _ = Subpacket::subpacket(&mut dup_buffer)?;
            }
            Ok(buffer)
        })?;
        Ok(SubpacketIterator { buffer })
    }

    /// Returns an empty iterator
    pub fn empty() -> Self {
        Self { buffer: Reader::empty() }
    }
}

impl<'a> Iterator for SubpacketIterator<'a> {
    type Item = Subpacket<'a>;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if self.buffer.is_empty() {
            return None;
        }
        Some(Subpacket::subpacket(&mut self.buffer).expect("buffer validated in constructor"))
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
