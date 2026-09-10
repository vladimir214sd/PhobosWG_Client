use std::path::PathBuf;
use std::process::Command;

fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=app.rc");
        println!("cargo:rerun-if-changed=assets/icon.ico");

        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let res_path = out_dir.join("app.res");
        let rc_path = PathBuf::from("app.rc");

        let rc_candidates = [
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\rc.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\rc.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\x64\rc.exe",
        ];

        let mut rc_found = None;
        if let Ok(output) = Command::new("where").arg("rc.exe").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(first_line) = stdout.lines().next() {
                    let path = first_line.trim();
                    if std::path::Path::new(path).exists() {
                        rc_found = Some(path.to_string());
                    }
                }
            }
        }

        if rc_found.is_none() {
            for c in &rc_candidates {
                if std::path::Path::new(c).exists() {
                    rc_found = Some(c.to_string());
                    break;
                }
            }
        }

        if let Some(rc_exe) = rc_found {
            let status = Command::new(rc_exe)
                .args(["/fo", res_path.to_str().unwrap(), rc_path.to_str().unwrap()])
                .status();

            if let Ok(s) = status {
                if s.success() {
                    println!("cargo:rustc-link-arg={}", res_path.display());
                }
            }
        }

        if std::env::var("PROFILE").unwrap_or_default() == "release" {
            println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
            println!("cargo:rustc-link-arg=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'");
        }
    }
}
