//! Routines for handling RPM tag data entries

use std;

/// An RPM tag data entry
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[repr(C)]
pub struct TagData {
    tag: u32,
    ty: u32,
    offset: u32,
    count: u32,
}

impl TagData {
    /// Creates a single [`TagData`] entry
    pub fn new(tag: u32, ty: u32, offset: u32, count: u32) -> Self {
        Self {
            tag: u32::to_be(tag),
            ty: u32::to_be(ty),
            offset: u32::to_be(offset),
            count: u32::to_be(count),
        }
    }

    /// Cast a slice of [`TagData`] to a slice of `u8`, without copying
    pub fn as_bytes<'a>(slice: &'a [Self]) -> &'a [u8] {
        // Static assertions
        let _: [u8; 16] = [0u8; size_of!(Self)];
        let _: [u8; 4] = [0u8; size_of!(u32)];
        let _: [u8; align_of!(u32)] = [0u8; align_of!(Self)];
        // SAFETY: we know that `TagData` cannot have any padding.  Since it has no padding, and
        // all bit patterns are valid for `u32`, all bit patterns are valid for `TagData` as well.
        unsafe {
            std::slice::from_raw_parts(slice.as_ptr() as *const u8, slice.len() * size_of!(Self))
        }
    }

    /// Cast a mutable slice of [`TagData`] to a mutable slice of `u8`, without copying
    ///
    /// This is safe:
    ///
    /// ```compile_fail
    /// # use rpm_parser::header::TagData;
    /// let mut i = [TagData::default()];
    /// let j = TagData::as_bytes_mut(&mut i);
    /// i[0];
    /// j[0]; // won’t compile
    /// ```
    pub fn as_bytes_mut<'a>(slice: &'a mut [Self]) -> &'a mut [u8] {
        // Static assertions
        let _: [u8; 16] = [0u8; size_of!(Self)];
        let _: [u8; 4] = [0u8; size_of!(u32)];
        let _: [u8; align_of!(u32)] = [0u8; align_of!(Self)];
        unsafe {
            let (ptr, len) = (slice.as_mut_ptr(), slice.len());
            // Forget `slice`, to avoid aliasing mutable references.
            std::mem::forget(slice);
            // SAFETY: we know that `TagData` cannot have any padding.  Since it
            // has no padding, and all bit patterns are valid for `u32`, all bit
            // patterns are valid for `TagData` as well.  Furthermore, since
            // `slice` is a unique reference, we know it was the only reference
            // to the data it points to.  We just ended its lifetime with
            // `std::mem::forget`, so now there are *no* references to that
            // data.  Therefore, the slice we produce will be the only reference
            // to the data, as required.  The multiplication cannot overflow
            // because a mutable slice cannot point to more than SIZE_MAX/2
            // bytes.
            std::slice::from_raw_parts_mut(ptr as *mut u8, len * size_of!(Self))
        }
    }
}

impl TagData {
    /// The tag
    pub fn tag(&self) -> u32 {
        u32::from_be(self.tag)
    }
    /// The type
    pub fn ty(&self) -> u32 {
        u32::from_be(self.ty)
    }
    /// The offset
    pub fn offset(&self) -> u32 {
        u32::from_be(self.offset)
    }
    /// The count
    pub fn count(&self) -> u32 {
        u32::from_be(self.count)
    }
}
