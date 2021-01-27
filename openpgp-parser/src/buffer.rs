//! A buffer for parsing untrusted data.  This is similar to, but distinct from, the `untrusted`
//! crate on `crates.io`.

use core::{convert::TryInto, mem::size_of};

/// A reader for untrusted data.  No method on this type will ever panic.
///
/// This type is guaranteed to have the same representation as `&'a [u8]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct Reader<'a> {
    untrusted_buffer: &'a [u8],
}

/// Error indicating end-of-file
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct EOFError;

impl<'a> Reader<'a> {
    /// Create a [`Reader`] from a slice of data.
    #[inline]
    pub fn new(untrusted_buffer: &'a [u8]) -> Self {
        Self { untrusted_buffer }
    }

    /// Returns the length of the data
    #[inline]
    pub fn len(&self) -> usize {
        self.untrusted_buffer.len()
    }

    /// Returns [`true`] if and only if the buffer is empty.
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// assert!(Reader::new(&[]).is_empty());
    /// assert!(!Reader::new(&[0]).is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.untrusted_buffer.is_empty()
    }

    /// Creates an empty reader
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// assert!(Reader::empty().is_empty());
    /// ```
    #[inline]
    pub fn empty() -> Self {
        Reader {
            untrusted_buffer: &b""[..],
        }
    }

    /// Read a single byte from the buffer.  Returns [`None`] if the buffer is
    /// empty.
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// assert!(Reader::empty().maybe_byte().is_none());
    /// let mut nonempty_reader = Reader::new(&[5][..]);
    /// assert_eq!(nonempty_reader.maybe_byte(), Some(5));
    /// assert!(nonempty_reader.maybe_byte().is_none());
    /// ```
    pub fn maybe_byte(&mut self) -> Option<u8> {
        let (&s, untrusted_rest) = self.untrusted_buffer.split_first()?;
        self.untrusted_buffer = untrusted_rest;
        Some(s)
    }

    /// Same as [`Self::maybe_byte`], but fails if the buffer is empty.
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::{Reader,EOFError};
    /// assert_eq!(Reader::empty().byte().unwrap_err(), EOFError);
    /// let mut nonempty_reader = Reader::new(&[5][..]);
    /// assert_eq!(nonempty_reader.byte(), Ok(5));
    /// assert_eq!(nonempty_reader.byte().unwrap_err(), EOFError);
    /// ```
    pub fn byte(&mut self) -> Result<u8, EOFError> {
        self.maybe_byte().ok_or(EOFError)
    }

    /// Gets a slice; this is less safe.
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// let mut nonempty_reader = Reader::new(&[5]);
    /// assert_eq!(nonempty_reader.as_untrusted_slice(), &[5]);
    /// ```
    #[inline]
    pub fn as_untrusted_slice(&self) -> &'a [u8] {
        self.untrusted_buffer
    }

    /// Gets a little-endian `u16` value
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// let mut reader = Reader::new(&[5, 6, 7]);
    /// assert_eq!(reader.le_u16(1).unwrap(), 0x706);
    /// assert!(reader.le_u16(2).is_err());
    /// assert!(reader.le_u16(usize::max_value()).is_err());
    /// ```
    #[inline]
    pub fn le_u16(&self, offset: usize) -> Result<u16, EOFError> {
        let range = offset..offset.wrapping_add(size_of::<u16>());
        let data = self.untrusted_buffer.get(range).ok_or(EOFError)?.try_into();
        // LLVM is able to optimize away the panic
        Ok(u16::from_le_bytes(data.expect("length is correct")))
    }

    /// Gets a little-endian `u32` value
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// let mut reader = Reader::new(&[5, 6, 7, 8, 9]);
    /// assert_eq!(reader.le_u32(1).unwrap(), 0x9080706);
    /// assert!(reader.le_u32(2).is_err());
    /// assert!(reader.le_u32(usize::max_value()).is_err());
    /// ```
    #[inline]
    pub fn le_u32(&self, offset: usize) -> Result<u32, EOFError> {
        let range = offset..offset.wrapping_add(size_of::<u32>());
        let data = self.untrusted_buffer.get(range).ok_or(EOFError)?.try_into();
        // LLVM is able to optimize away the panic
        Ok(u32::from_le_bytes(data.expect("length is correct")))
    }

    /// Gets a little-endian `u64` value
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// let mut reader = Reader::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    /// assert_eq!(reader.le_u64(2).unwrap(), 0x908070605040302);
    /// assert!(reader.le_u64(3).is_err());
    /// assert!(reader.le_u64(usize::max_value()).is_err());
    /// ```
    #[inline]
    pub fn le_u64(&self, offset: usize) -> Result<u64, EOFError> {
        let range = offset..offset.wrapping_add(size_of::<u64>());
        let data = self.untrusted_buffer.get(range).ok_or(EOFError)?.try_into();
        // LLVM is able to optimize away the panic
        Ok(u64::from_le_bytes(data.expect("length is correct")))
    }

    /// Gets a little-endian `u16` value
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// let mut reader = Reader::new(&[5, 6, 7]);
    /// assert_eq!(reader.be_u16(1).unwrap(), 0x607);
    /// assert!(reader.be_u16(2).is_err());
    /// assert!(reader.be_u16(usize::max_value()).is_err());
    /// ```
    #[inline]
    pub fn be_u16(&self, offset: usize) -> Result<u16, EOFError> {
        let range = offset..offset.wrapping_add(size_of::<u16>());
        let data = self.untrusted_buffer.get(range).ok_or(EOFError)?.try_into();
        // LLVM is able to optimize away the panic
        Ok(u16::from_be_bytes(data.expect("length is correct")))
    }

    /// Gets a little-endian `u32` value
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// let mut reader = Reader::new(&[5, 6, 7, 8, 9]);
    /// assert_eq!(reader.be_u32(1).unwrap(), 0x6070809);
    /// assert!(reader.be_u32(2).is_err());
    /// assert!(reader.be_u32(usize::max_value()).is_err());
    /// ```
    #[inline]
    pub fn be_u32(&self, offset: usize) -> Result<u32, EOFError> {
        let range = offset..offset.wrapping_add(size_of::<u32>());
        let data = self.untrusted_buffer.get(range).ok_or(EOFError)?.try_into();
        // LLVM is able to optimize away the panic
        Ok(u32::from_be_bytes(data.expect("length is correct")))
    }

    /// Gets a little-endian `u64` value
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// let mut reader = Reader::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    /// assert_eq!(reader.be_u64(2).unwrap(), 0x203040506070809);
    /// assert!(reader.be_u64(3).is_err());
    /// assert!(reader.be_u64(usize::max_value()).is_err());
    /// ```
    #[inline]
    pub fn be_u64(&self, offset: usize) -> Result<u64, EOFError> {
        let range = offset..offset.wrapping_add(size_of::<u64>());
        let data = self.untrusted_buffer.get(range).ok_or(EOFError)?.try_into();
        // LLVM is able to optimize away the panic
        Ok(u64::from_be_bytes(data.expect("length is correct")))
    }

    /// Gets `len` bytes as a [`Reader`].
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// let mut reader = Reader::new(&[50, 6, 3]);
    /// assert!(reader.get(5).is_err());
    /// assert_eq!(reader.get(2).unwrap(), Reader::new(&[50, 6]));
    /// assert_eq!(reader.get(1).unwrap(), Reader::new(&[3]));
    /// assert!(reader.is_empty());
    /// ```
    pub fn get(&mut self, len: usize) -> Result<Self, EOFError> {
        if len > self.untrusted_buffer.len() {
            Err(EOFError)
        } else {
            let (untrusted_buffer, untrusted_rest) = self.untrusted_buffer.split_at(len);
            self.untrusted_buffer = untrusted_rest;
            Ok(Self { untrusted_buffer })
        }
    }

    /// Call the given callback with a copy of `self`.  If the callback
    /// succeeds, `self` is updated to match the copy.
    ///
    /// ```rust
    /// # use openpgp_parser::buffer::Reader;
    /// let mut reader = Reader::new(&[50, 6, 3]);
    /// assert!(reader.get(5).is_err());
    /// assert_eq!(reader.get(2).unwrap(), Reader::new(&[50, 6]));
    /// assert_eq!(reader.get(1).unwrap(), Reader::new(&[3]));
    /// assert!(reader.is_empty());
    /// ```
    pub fn read<T, U, V: FnOnce(&mut Self) -> Result<T, U>>(&mut self, cb: V) -> Result<T, U> {
        let mut dup = self.clone();
        let retval = cb(&mut dup)?;
        *self = dup;
        Ok(retval)
    }

    /// Call the given callback with a copy of `self`.  If the callback
    /// fails, return that error.  If the callback succeeds, it is expected to
    /// consume the whole buffer; otherwise, `trailing_junk` is returned.
    pub fn read_all<T, U, V: FnOnce(&mut Self) -> Result<T, U>>(
        &mut self,
        trailing_junk: U,
        cb: V,
    ) -> Result<T, U> {
        let mut dup = self.clone();
        let retval = cb(&mut dup)?;
        match dup.is_empty() {
            true => Ok(retval),
            false => Err(trailing_junk),
        }
    }
}

impl From<EOFError> for super::Error {
    fn from(EOFError: EOFError) -> super::Error {
        super::Error::PrematureEOF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_one_byte() {
        let mut buffer = Reader::new(b"abc");
        assert_eq!(buffer.get(4), Err(EOFError));
        assert_eq!(buffer.maybe_byte(), Some(b'a'));
        assert_eq!(buffer.get(2), Ok(Reader::new(&b"bc"[..])));
        assert_eq!(buffer.get(2), Err(EOFError));
        assert!(buffer.maybe_byte().is_none());
        assert!(buffer.byte().is_err());
    }

    #[test]
    fn read() {
        let mut buffer = Reader::new(b"a");
        buffer
            .read::<_, (), _>(|b| {
                assert_eq!(b.maybe_byte(), Some(b'a'));
                assert!(b.maybe_byte().is_none());
                assert!(b.byte().is_err());
                Ok(())
            })
            .unwrap();
        assert!(buffer.maybe_byte().is_none());
        buffer = Reader::new(b"b");
        buffer
            .read::<(), _, _>(|b| {
                assert_eq!(b.maybe_byte(), Some(b'b'));
                assert!(b.maybe_byte().is_none());
                assert!(b.byte().is_err());
                Err(())
            })
            .unwrap_err();
        assert_eq!(buffer.maybe_byte(), Some(b'b'));
        assert!(buffer.maybe_byte().is_none());
        assert!(buffer.byte().is_err());
    }
}
