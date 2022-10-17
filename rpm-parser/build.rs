use std::env;
use std::process;

fn main() {
    let rustc = env::var("RUSTC").unwrap();
    let output = process::Command::new(rustc)
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success(), "`rustc --version` failed");
    let version = String::from_utf8(output.stdout).expect("rustc wrote invalid UTF-8?");
    let mut ellipsis_inclusive_range_deprecated = true;
    let mut bare_trait_obj_deprecated = true;
    if version.starts_with("rustc 1.") {
        let version = &version[8..];
        if let Some(period) = version.find('.') {
            if let Ok(vnum) = version[..period].parse::<u32>() {
                bare_trait_obj_deprecated = vnum >= 37;
                ellipsis_inclusive_range_deprecated = vnum >= 37;
            }
        }
    }
    if bare_trait_obj_deprecated {
        println!("cargo:rustc-cfg=bare_trait_obj_deprecated");
    } else {
        println!("cargo:rustc-cfg=bare_trait_obj_allowed");
    }
    if ellipsis_inclusive_range_deprecated {
        println!("cargo:rustc-cfg=ellipsis_inclusive_range_deprecated");
    } else {
        println!("cargo:rustc-cfg=ellipsis_inclusive_range_allowed");
    }
}
