//! FFI code

#[link(name = "rpm")]
extern "C" {
    fn rpmTagGetType(tag: std::os::raw::c_int) -> std::os::raw::c_int;
    fn rpmTagTypeGetClass(tag: std::os::raw::c_int) -> std::os::raw::c_int;
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TagType {
    Char = 1,
    Int8 = 2,
    Int16 = 3,
    Int32 = 4,
    Int64 = 5,
    String = 6,
    Bin = 7,
    StringArray = 8,
    I18NString = 9,
}

pub fn tag_type(tag: u32) -> Option<(TagType, bool)> {
    if tag > 0x7FFF {
        return None;
    }
    let ty = unsafe { rpmTagGetType(tag as _) };
    let is_array = match ty as u32 & 0xffff_0000 {
        0x10000 => false,
        0x20000 => true,
        // This should probably be a panic, but RPM does define
        // RPM_MAPPING_RETURN_TYPE, so just fail.
        _ => {
            if cfg!(test) && ty != 0 {
                panic!("bad return from RPM")
            } else {
                return None;
            }
        }
    };
    Some((
        match ty & 0xffff {
            0 => return None,
            1 => TagType::Char,
            2 => TagType::Int8,
            3 => TagType::Int16,
            4 => TagType::Int32,
            5 => TagType::Int64,
            6 => TagType::String,
            7 => TagType::Bin,
            8 => TagType::StringArray,
            9 => TagType::I18NString,
            _ => unreachable!("invalid return from rpmTagGetTagType()"),
        },
        is_array,
    ))
}

pub fn tag_class(ty: TagType) -> std::os::raw::c_int {
    unsafe { rpmTagTypeGetClass(ty as _) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_rpm_return() {
        for i in 0..0x8000 {
            tag_type(i);
        }
    }
}
