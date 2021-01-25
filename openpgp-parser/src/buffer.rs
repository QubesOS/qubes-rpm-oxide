//! A buffer for parsing untrusted data.  This is similar to, but distinct from, the `untrusted`
//! crate on `crates.io`.

/// A reader for untrusted data.  No method on this type will ever panic.
#[derive(Copy, Clone, Debug)]
pub struct Reader<'a> {
    untrusted_buffer: &'a [u8],
}

/// Error indicating end-of-file
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct EOFError;

impl<'a> Reader<'a> {
    /// Create a [`Reader`] from a slice of data.
    pub fn new(untrusted_buffer: &'a [u8]) -> Self {
        Self {
            untrusted_buffer,
        }
    }

    /// Read a single byte from the buffer.  Returns [`None`] if the buffer is
    /// empty.
    pub fn maybe_byte(&mut self) -> Option<u8> {
        let (&s, untrusted_rest) = self.untrusted_buffer.split_first()?;
        self.untrusted_buffer = untrusted_rest;
        Some(s)
    }

    /// Same as [`Self::maybe_byte`], but fails if the buffer is empty.
    pub fn byte(&mut self) -> Result<u8, EOFError> {
        self.maybe_byte().ok_or(EOFError)
    }

    /// Gets `len` bytes as a slice.  FIXME return a `Reader` instead.
    pub fn get(&mut self, len: usize) -> Result<&'a [u8], EOFError> {
        if len > self.untrusted_buffer.len() {
            Err(EOFError)
        } else {
            let (first, rest) = self.untrusted_buffer.split_at(len);
            self.untrusted_buffer = rest;
            Ok(first)
        }
    }

    /// Call the given callback with a copy of `self`.  If the callback
    /// succeeds, `self` is updated to match the copy.
    pub fn read<T, U, V: FnOnce(&mut Self) -> Result<T, U>>(&mut self, cb: V) -> Result<T, U> {
        let mut dup = *self;
        let retval = cb(&mut dup)?;
        *self = dup;
        Ok(retval)
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
        assert_eq!(buffer.get(2), Ok(&b"bc"[..]));
        assert_eq!(buffer.get(2), Err(EOFError));
        assert!(buffer.maybe_byte().is_none());
        assert!(buffer.byte().is_err());
    }

    #[test]
    fn read() {
        let mut buffer = Reader::new(b"a");
        buffer.read::<_, (), _>(|b| {
            assert_eq!(b.maybe_byte(), Some(b'a'));
            assert!(b.maybe_byte().is_none());
            assert!(b.byte().is_err());
            Ok(())
        }).unwrap();
        assert!(buffer.maybe_byte().is_none());
        buffer = Reader::new(b"b");
        buffer.read::<(), _, _>(|b| {
            assert_eq!(b.maybe_byte(), Some(b'b'));
            assert!(b.maybe_byte().is_none());
            assert!(b.byte().is_err());
            Err(())
        }).unwrap_err();
        assert_eq!(buffer.maybe_byte(), Some(b'b'));
        assert!(buffer.maybe_byte().is_none());
        assert!(buffer.byte().is_err());
    }
}

