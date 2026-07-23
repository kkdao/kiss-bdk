use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let quirc = manifest.join("vendor/k_quirc");
    let sources = [
        "src/k_quirc.c",
        "src/k_quirc_version.c",
        "src/k_quirc_identify.c",
        "src/k_quirc_decode.c",
    ];

    let mut build = cc::Build::new();
    build
        .include(quirc.join("include"))
        .include(quirc.join("src"))
        .include(manifest.join("native/include"))
        .define("K_QUIRC_ADAPTIVE_THRESHOLD", None)
        .define("K_QUIRC_BILINEAR_THRESHOLD", None)
        .warnings(false);
    for source in sources {
        let path = quirc.join(source);
        println!("cargo:rerun-if-changed={}", path.display());
        build.file(path);
    }
    build.file(manifest.join("native/k_quirc_bridge.c"));
    println!(
        "cargo:rerun-if-changed={}",
        quirc.join("include/k_quirc.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        quirc.join("src/k_quirc_internal.h").display()
    );
    println!("cargo:rerun-if-changed=native/include/esp_log.h");
    println!("cargo:rerun-if-changed=native/include/freertos/FreeRTOS.h");
    println!("cargo:rerun-if-changed=native/include/freertos/task.h");
    println!("cargo:rerun-if-changed=native/k_quirc_bridge.c");
    build.compile("kiss_k_quirc");

    if env::var("CARGO_CFG_TARGET_FAMILY").as_deref() == Ok("unix")
        && env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
    {
        println!("cargo:rustc-link-lib=m");
    }
}
