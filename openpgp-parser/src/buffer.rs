//! A buffer for parsing untrusted data.  This is similar to, but distinct from, the `untrusted`
//! crate on `crates.io`.

#[cfg(not(feature = "std"))]
use core::mem::size_of;
#[cfg(feature = "std")]
use std::mem::size_of;
#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
impl From<EOFError> for std::io::Error {
    fn from(_: EOFError) -> Self {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Unexpected EOF")
    }
}

/// A reader for untrusted data.  No method on this type will ever panic.
///
/// This type is guaranteed to have the same representation as `&'a [u8]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Reader<'a> {
    untrusted_buffer: &'a [u8],
}

/// Error indicating end-of-file
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct EOFError;

macro_rules! gen_be_offset {
    ($($(#[$s:meta])* ($i: ident, $t: ty))+) => {$(
        $(#[$s])*
        pub fn $i(&self, offset: usize) -> Result<$t, EOFError> {
            let range = offset..offset.wrapping_add(size_of::<$t>());
            let data = self.untrusted_buffer.get(range).ok_or(EOFError)?;
            let mut res: $t = 0;
            for i in 0..size_of::<$t>() {
                res = res << 8 | data[i] as $t
            }
            Ok(res)
        }
    )+};
}

macro_rules! gen_le {
    ($($(#[$s:meta])* ($i: ident, $t: ty))+) => {$(
        $(#[$s])*
        #[inline]
        pub fn $i(&mut self) -> Result<$t, EOFError> {
            let untrusted_buffer = self.get_bytes(size_of::<$t>())?;
            let mut res: $t = 0;
            for i in 0..size_of::<$t>() {
                res = res << 8 | untrusted_buffer[size_of::<$t>() - 1 - i] as $t
            }
            Ok(res)
        }
    )+}
}

macro_rules! gen_be {
    ($($(#[$s:meta])* ($i: ident, $t: ty))+) => {$(
        $(#[$s])*
        #[inline]
        pub fn $i(&mut self) -> Result<$t, EOFError> {
            let untrusted_buffer = self.get_bytes(size_of::<$t>())?;
            let mut res: $t = 0;
            for i in 0..size_of::<$t>() {
                res = res << 8 | untrusted_buffer[i] as $t
            }
            Ok(res)
        }
    )+}
}

macro_rules! gen_le_offset {
    ($($(#[$s:meta])* ($i: ident, $t: ty))+) => {$(
        $(#[$s])*
        #[inline]
        pub fn $i(&self, offset: usize) -> Result<$t, EOFError> {
            let range = offset..offset.wrapping_add(size_of::<$t>());
            let data = self.untrusted_buffer.get(range).ok_or(EOFError)?;
            let mut res: $t = 0;
            for i in 0..size_of::<$t>() {
                res = res << 8 | data[size_of::<$t>() - 1 - i] as $t
            }
            Ok(res)
        }
    )+}
}

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
    /// # use openpgp_parser::Reader;
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
    /// # use openpgp_parser::Reader;
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
    /// # use openpgp_parser::Reader;
    /// assert!(Reader::empty().maybe_byte().is_none());
    /// let mut nonempty_reader = Reader::new(&[5][..]);
    /// assert_eq!(nonempty_reader.maybe_byte(), Some(5));
    /// assert!(nonempty_reader.maybe_byte().is_none());
    /// ```
    pub fn maybe_byte(&mut self) -> Option<u8> {
        self.untrusted_buffer
            .split_first()
            .map(|(&s, untrusted_rest)| {
                self.untrusted_buffer = untrusted_rest;
                s
            })
    }

    /// Same as [`Self::maybe_byte`], but fails if the buffer is empty.
    ///
    /// ```rust
    /// # use openpgp_parser::{Reader,EOFError};
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
    /// # use openpgp_parser::Reader;
    /// let mut nonempty_reader = Reader::new(&[5]);
    /// assert_eq!(nonempty_reader.as_untrusted_slice(), &[5]);
    /// ```
    #[inline]
    pub fn as_untrusted_slice(&self) -> &'a [u8] {
        self.untrusted_buffer
    }

    gen_le! {
        /// Gets a little-endian `u16` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[5, 6, 7]);
        /// assert_eq!(reader.le_u16().unwrap(), 0x605);
        /// assert!(reader.le_u16().is_err());
        /// assert_eq!(reader.as_untrusted_slice(), &[0x7]);
        /// ```
        (le_u16, u16)

        /// Gets a little-endian `u32` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[5, 6, 7, 8, 9]);
        /// assert_eq!(reader.le_u32().unwrap(), 0x8070605);
        /// assert!(reader.le_u32().is_err());
        /// assert_eq!(reader.as_untrusted_slice(), &[0x9]);
        /// ```
        (le_u32, u32)

        /// Gets a little-endian `u64` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        /// assert_eq!(reader.le_u64().unwrap(), 0x706050403020100);
        /// assert!(reader.le_u64().is_err());
        /// assert_eq!(reader.as_untrusted_slice(), &[0x8, 0x9]);
        /// ```
        (le_u64, u64)
    }

    gen_be! {
        /// Gets a big-endian `u16` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[5, 6, 7]);
        /// assert_eq!(reader.be_u16().unwrap(), 0x506);
        /// assert!(reader.be_u16().is_err());
        /// assert_eq!(reader.as_untrusted_slice(), &[0x7]);
        /// ```
        (be_u16, u16)

        /// Gets a big-endian `u32` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[5, 6, 7, 8, 9]);
        /// assert_eq!(reader.be_u32().unwrap(), 0x5060708);
        /// assert!(reader.be_u32().is_err());
        /// assert_eq!(reader.as_untrusted_slice(), &[0x9]);
        /// ```
        (be_u32, u32)

        /// Gets a big-endian `u64` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        /// assert_eq!(reader.be_u64().unwrap(), 0x1020304050607);
        /// assert!(reader.be_u64().is_err());
        /// assert_eq!(reader.as_untrusted_slice(), &[0x8, 0x9]);
        /// ```
        (be_u64, u64)
    }

    gen_le_offset! {
        /// Gets a little-endian `u16` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[5, 6, 7]);
        /// assert_eq!(reader.le_u16_offset(1).unwrap(), 0x706);
        /// assert!(reader.le_u16_offset(2).is_err());
        /// assert!(reader.le_u16_offset(usize::max_value()).is_err());
        /// ```
        (le_u16_offset, u16)

        /// Gets a little-endian `u32` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[5, 6, 7, 8, 9]);
        /// assert_eq!(reader.le_u32_offset(1).unwrap(), 0x9080706);
        /// assert!(reader.le_u32_offset(2).is_err());
        /// assert!(reader.le_u32_offset(usize::max_value()).is_err());
        /// ```
        (le_u32_offset, u32)

        /// Gets a little-endian `u64` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        /// assert_eq!(reader.le_u64_offset(2).unwrap(), 0x908070605040302);
        /// assert!(reader.le_u64_offset(3).is_err());
        /// assert!(reader.le_u64_offset(usize::max_value()).is_err());
        /// ```
        (le_u64_offset, u64)
    }

    gen_be_offset! {
        /// Gets a big-endian `u16` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[5, 6, 7]);
        /// assert_eq!(reader.be_u16_offset(1).unwrap(), 0x607);
        /// assert!(reader.be_u16_offset(2).is_err());
        /// assert!(reader.be_u16_offset(usize::max_value()).is_err());
        /// ```
        (be_u16_offset, u16)

        /// Gets a big-endian `u32` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[5, 6, 7, 8, 9]);
        /// assert_eq!(reader.be_u32_offset(1).unwrap(), 0x6070809);
        /// assert!(reader.be_u32_offset(2).is_err());
        /// assert!(reader.be_u32_offset(usize::max_value()).is_err());
        /// ```
        (be_u32_offset, u32)

        /// Gets a big-endian `u64` value
        ///
        /// ```rust
        /// # use openpgp_parser::Reader;
        /// let mut reader = Reader::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        /// assert_eq!(reader.be_u64_offset(2).unwrap(), 0x203040506070809);
        /// assert!(reader.be_u64_offset(3).is_err());
        /// assert!(reader.be_u64_offset(usize::max_value()).is_err());
        /// ```
        (be_u64_offset,u64)
    }

    /// Gets `len` bytes as a byte slice.  Mostly useful when processing the
    /// data manually.
    ///
    /// ```rust
    /// # use openpgp_parser::Reader;
    /// let mut reader = Reader::new(&[50, 6, 3]);
    /// assert!(reader.get_bytes(5).is_err());
    /// assert_eq!(reader.get_bytes(2).unwrap(), &[50, 6]);
    /// assert_eq!(reader.get_bytes(1).unwrap(), &[3]);
    /// assert!(reader.is_empty());
    /// ```
    pub fn get_bytes(&mut self, len: usize) -> Result<&'a [u8], EOFError> {
        if len > self.untrusted_buffer.len() {
            Err(EOFError)
        } else {
            let (untrusted_buffer, untrusted_rest) = self.untrusted_buffer.split_at(len);
            self.untrusted_buffer = untrusted_rest;
            Ok(untrusted_buffer)
        }
    }

    /// Reads `len` bytes of data, then calls `cb` with the result.  `cb` must use all of those
    /// bytes, otherwise `trailing_junk` is returned.
    pub fn read_bytes<T, U, V: Fn(&mut Self) -> Result<T, U>>(
        &mut self,
        len: usize,
        trailing_junk: U,
        cb: V,
    ) -> Result<T, U> {
        if len > self.untrusted_buffer.len() {
            Err(trailing_junk)
        } else {
            let (untrusted_buffer, untrusted_rest) = self.untrusted_buffer.split_at(len);
            let retval = cb(&mut Self { untrusted_buffer })?;
            if !untrusted_buffer.is_empty() {
                return Err(trailing_junk);
            }
            self.untrusted_buffer = untrusted_rest;
            Ok(retval)
        }
    }

    /// Call the given callback with a copy of `self`.  If the callback
    /// succeeds, `self` is updated to match the copy.
    ///
    /// ```rust
    /// # use openpgp_parser::{Reader, Error};
    /// let mut reader = Reader::new(&[50, 6, 3]);
    /// reader.read(|s| {
    ///     s.get_bytes(3).unwrap(); // will succeed
    ///     s.get_bytes(1) // fails
    /// }).unwrap_err();
    /// assert_eq!(reader.len(), 3); // the reader has not been changed
    /// let () = reader.read::<_, Error, _>(|s| {
    ///     s.get_bytes(2)?;
    ///     s.get_bytes(1)?;
    ///     Ok(())
    /// }).unwrap();
    /// assert!(reader.is_empty()); // reader has been changed
    /// ```
    pub fn read<T, U, V: FnOnce(&mut Self) -> Result<T, U>>(&mut self, cb: V) -> Result<T, U> {
        let mut dup = self.clone();
        let retval = cb(&mut dup)?;
        *self = dup;
        Ok(retval)
    }

    /// Same as [`Self::read`], except that on success, it also returns a buffer
    /// containing the bytes read.
    ///
    /// ```rust
    /// # use openpgp_parser::{Reader, Error};
    /// let mut reader = Reader::new(&[50, 6, 3]);
    /// reader.read(|s| {
    ///     s.get_bytes(3).unwrap(); // will succeed
    ///     s.get_bytes(1) // fails
    /// }).unwrap_err();
    /// assert_eq!(reader.len(), 3); // the reader has not been changed
    /// let (new_reader, ()) = reader.get_read::<_, Error, _>(|s| {
    ///     s.get_bytes(2)?;
    ///     s.get_bytes(1)?;
    ///     Ok(())
    /// }).unwrap();
    /// assert!(reader.is_empty()); // reader has been changed
    /// assert_eq!(new_reader.as_untrusted_slice(), &[50, 6, 3]);
    /// ```
    pub fn get_read<T, U, V: FnOnce(&mut Self) -> Result<T, U>>(
        &mut self,
        cb: V,
    ) -> Result<(Self, T), U> {
        let mut dup = self.clone();
        let retval = cb(&mut dup)?;
        let ret_buf = Self {
            untrusted_buffer: &self.untrusted_buffer[..self.len() - dup.len()],
        };
        *self = dup;
        Ok((ret_buf, retval))
    }

    /// Call the given callback with a copy of `self`.  If the callback
    /// fails, return that error.  If the callback succeeds, it is expected to
    /// consume the whole buffer; otherwise, `trailing_junk` is returned.
    pub fn read_all<T, U, V: FnOnce(&mut Self) -> Result<T, U>>(
        untrusted_buffer: &'a [u8],
        trailing_junk: U,
        cb: V,
    ) -> Result<T, U> {
        let mut reader = Self { untrusted_buffer };
        let retval = cb(&mut reader)?;
        match reader.is_empty() {
            true => Ok(retval),
            false => Err(trailing_junk),
        }
    }
}

impl From<EOFError> for super::Error {
    fn from(_: EOFError) -> super::Error {
        super::Error::PrematureEOF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_one_byte() {
        let mut buffer = Reader::new(b"abc");
        assert_eq!(buffer.get_bytes(4), Err(EOFError));
        assert_eq!(buffer.maybe_byte(), Some(b'a'));
        assert_eq!(buffer.get_bytes(2), Ok(&b"bc"[..]));
        assert_eq!(buffer.get_bytes(2), Err(EOFError));
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
