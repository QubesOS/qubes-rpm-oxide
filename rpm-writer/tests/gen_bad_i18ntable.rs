extern crate openpgp_parser;
extern crate rpm_crypto;
extern crate rpm_parser;
extern crate rpm_writer;
use openpgp_parser::signature::AllowWeakHashes;
use rpm_writer::{HeaderBuilder, HeaderEntry, HeaderKind};
use std::ffi::CStr;
const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_OS: u32 = 1021;
const RPMTAG_ARCH: u32 = 1022;
#[test]
fn bad_i18ntable_rejected() {
    let i18nstring1 = vec![
        CStr::from_bytes_with_nul(b"alpha\0").unwrap(),
        CStr::from_bytes_with_nul(b"beta\0").unwrap(),
    ];
    let i18ntable = vec![
        CStr::from_bytes_with_nul(b"alpha\0").unwrap(),
        CStr::from_bytes_with_nul(b"beta\0").unwrap(),
    ];
    let i18nstring2 = vec![
        CStr::from_bytes_with_nul(b"alpha\0").unwrap(),
        CStr::from_bytes_with_nul(b"beta\0").unwrap(),
        CStr::from_bytes_with_nul(b"gamma\0").unwrap(),
    ];
    let i18nstring3 = vec![CStr::from_bytes_with_nul(b"alpha\0").unwrap()];
    {
        let mut main_builder = HeaderBuilder::new(HeaderKind::Main);
        let name = CStr::from_bytes_with_nul(b"fake_name\0").unwrap();
        let version = CStr::from_bytes_with_nul(b"fake_version\0").unwrap();
        let release = CStr::from_bytes_with_nul(b"fake_release\0").unwrap();
        let os = CStr::from_bytes_with_nul(b"fake_os\0").unwrap();
        let arch = CStr::from_bytes_with_nul(b"fake_arch\0").unwrap();
        main_builder.push(RPMTAG_NAME, HeaderEntry::String(name));
        main_builder.push(RPMTAG_VERSION, HeaderEntry::String(version));
        main_builder.push(RPMTAG_RELEASE, HeaderEntry::String(release));
        main_builder.push(RPMTAG_OS, HeaderEntry::String(os));
        main_builder.push(RPMTAG_ARCH, HeaderEntry::String(arch));
        main_builder.push(1047, HeaderEntry::I18NTable(&i18nstring1));
        let mut v: Vec<u8> = vec![];
        main_builder.emit(&mut v).unwrap();
        let token = rpm_crypto::init(None);
        let no_table_emsg = rpm_parser::load_immutable(&mut &v[..], token)
            .map(drop)
            .unwrap_err()
            .to_string();
        assert!(no_table_emsg.starts_with("No I18N table found, yet I18Nstring present"));
        main_builder.push(100, HeaderEntry::I18NTable(&i18ntable));
        v.clear();
        main_builder.emit(&mut v).unwrap();
        let bad_table_emsg = rpm_parser::load_immutable(&mut &v[..], token)
            .map(drop)
            .unwrap_err()
            .to_string();
        assert_eq!(bad_table_emsg, "Invalid I18NTable");
        main_builder.push(100, HeaderEntry::StringArray(&i18ntable));
        v.clear();
        main_builder.emit(&mut v).unwrap();
        let header = rpm_parser::load_immutable(&mut &v[..], token).unwrap();

        assert_eq!(header.os, "fake_os");
        assert_eq!(header.name, "fake_name");
        assert_eq!(header.release, "fake_release");
        assert_eq!(header.arch, "fake_arch");
        assert_eq!(header.version, "fake_version");
        main_builder.push(100, HeaderEntry::StringArray(&i18ntable));
        main_builder
            .push(1047, HeaderEntry::I18NTable(&i18nstring2))
            .unwrap();
        v.clear();
        main_builder.emit(&mut v).unwrap();
        rpm_parser::load_immutable(&mut &v[..], token)
            .map(drop)
            .unwrap_err();
        assert_eq!(
            main_builder
                .push(1047, HeaderEntry::I18NTable(&i18nstring3))
                .unwrap()
                .len(),
            17
        );
        v.clear();
        main_builder.emit(&mut v).unwrap();
        rpm_parser::load_immutable(&mut &v[..], token)
            .map(drop)
            .unwrap_err();
        assert_eq!(
            main_builder
                .push(1047, HeaderEntry::String(i18nstring3[0]))
                .unwrap()
                .len(),
            6
        );
        v.clear();
        main_builder.emit(&mut v).unwrap();
        rpm_parser::load_immutable(&mut &v[..], token)
            .map(drop)
            .unwrap();
    }
}

#[test]
fn no_i18ntable_in_signature_header() {
    let i18ntable = &[
        CStr::from_bytes_with_nul(b"alpha\0").unwrap(),
        CStr::from_bytes_with_nul(b"beta\0").unwrap(),
    ];
    let mut builder = HeaderBuilder::new(HeaderKind::Signature);
    builder.push(100, HeaderEntry::StringArray(i18ntable));
    let token = rpm_crypto::init(None);
    let mut v = vec![];
    builder.emit(&mut v).unwrap();
    assert_eq!(
        rpm_parser::load_signature(&mut &v[..], AllowWeakHashes::No, token)
            .map(drop)
            .unwrap_err()
            .to_string(),
        "I18Nstring not permitted in signature header"
    );
    v.clear();
    builder = HeaderBuilder::new(HeaderKind::Signature);
    builder.push(1047, HeaderEntry::I18NTable(i18ntable));
    builder.emit(&mut v).unwrap();
    assert_eq!(
        rpm_parser::load_signature(&mut &v[..], AllowWeakHashes::No, token)
            .map(drop)
            .unwrap_err()
            .to_string(),
        "I18Nstring not permitted in signature header"
    );
}
