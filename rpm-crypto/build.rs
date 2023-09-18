fn main() {
    cc::Build::new()
        .file("ffi.c")
        .include("/usr/include")
        .compile("qubes-rpm-lib");
    println!("cargo:rerun-if-changed=ffi.c");
    println!("cargo:rustc-link-lib=dylib=rpm");
    println!("cargo:rustc-link-lib=dylib=rpmio");
}
