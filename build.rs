use std::{env, fs};

fn main() {
    embuild::espidf::sysenv::output();
    // Wi-Fi credentials from cfg.toml (gitignored; see cfg.toml.example); WIFI_SSID and WIFI_PASS override.
    println!("cargo:rerun-if-changed=cfg.toml");
    let file: toml::Table = fs::read_to_string("cfg.toml")
        .unwrap_or_default()
        .parse()
        .expect("valid cfg.toml");
    for (var, key) in [("WIFI_SSID", "ssid"), ("WIFI_PASS", "password")] {
        let value = env::var(var).ok().or_else(|| file.get("wifi")?.get(key)?.as_str().map(str::to_owned));
        let value = value.unwrap_or_else(|| panic!("set [wifi] {key} in cfg.toml or {var} in the environment"));
        println!("cargo:rustc-env={var}={value}");
    }
}
