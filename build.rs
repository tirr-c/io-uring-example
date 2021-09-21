use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=io_uring_wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("io_uring_wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .allowlist_type("io_uring_.*")
        .allowlist_var("IORING_.*")
        .allowlist_function("io_uring_.*")
        .generate()
        .expect("Failed to generate bindings");

    let out_path = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("io_uring_bindings.rs"))
        .expect("Failed to write bindings");
}
