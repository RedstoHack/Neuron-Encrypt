use std::process::Command;

fn main() {
    let git_hash = if std::env::var("SOURCE_DATE_EPOCH").is_ok() {
        "unknown".to_string()
    } else {
        Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|| "unknown".to_owned())
    };

    println!("cargo:rustc-env=GIT_HASH={git_hash}");
    println!("cargo:rerun-if-changed=.git/HEAD");

    // Windows: embed the brand icon (app.rc -> assets/icon.ico) so the .exe
    // file, taskbar, shortcuts and Add/Remove Programs all show the same
    // artwork as the in-app window icon. Soft-fail (warning only) so
    // toolchains without windres (e.g. MSVC without SDK tools on PATH)
    // still build exactly like before.
    #[cfg(windows)]
    {
        let out_dir = std::env::var("OUT_DIR").unwrap_or_default();
        let res_path = format!("{out_dir}/app-icon.res");
        let compiled = Command::new("windres")
            .args(["app.rc", "-O", "coff", "-o", res_path.as_str()])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if compiled {
            println!("cargo:rustc-link-arg={res_path}");
        } else {
            println!("cargo:warning=icon resource not embedded (windres unavailable)");
        }
    }
}
