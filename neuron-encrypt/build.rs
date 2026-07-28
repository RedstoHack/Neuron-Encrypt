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
}
