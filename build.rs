fn main() {
    println!("cargo:rustc-check-cfg=cfg(swapx25519hybrid)");
    // Use liboqs version as a proxy for oqs-provider version.
    //
    // On oqsprovider < 0.7.0 (which is installed on fedora 41, the distro used in CI)
    // we need to swap the classical and post quantum parts of both the public key
    // and the secret for X25519 hybrid keys.
    if let Ok(lib) = pkg_config::probe_library("liboqs") {
        let parts = lib.version.split('.').collect::<Vec<_>>();

        if let [major, minor] = parts[..2] {
            let major = major.parse::<u32>().unwrap();
            let minor = minor.parse::<u32>().unwrap();

            if major < 1 && minor < 12 {
                println!("cargo:rustc-cfg=swapx25519hybrid");
            }
        }
    }
}
