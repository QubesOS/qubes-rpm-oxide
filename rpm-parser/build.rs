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
    let mut try_from_unstable = false;
    let mut ellipsis_inclusive_range_deprecated = true;
    let mut bare_trait_obj_deprecated = true;
    let mut alloc_crate_unstable = false;
    if version.starts_with("rustc 1.") {
        let version = &version[8..];
        if let Some(period) = version.find('.') {
            if let Ok(vnum) = version[..period].parse::<u32>() {
                try_from_unstable = vnum < 34;
                alloc_crate_unstable = vnum < 36;
                bare_trait_obj_deprecated = vnum >= 37;
                ellipsis_inclusive_range_deprecated = vnum >= 37;
            }
        }
    }
    if try_from_unstable {
        println!("cargo:rustc-cfg=try_from_unstable");
    } else {
        println!("cargo:rustc-cfg=try_from_stable");
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
    if alloc_crate_unstable {
        println!("cargo:rustc-cfg=alloc_crate_unstable");
        // turn on nightly features on these old compilers
        println!("cargo:rustc-env=RUSTC_BOOTSTRAP=1");
    } else {
        println!("cargo:rustc-cfg=alloc_crate_stable");
    }
}
