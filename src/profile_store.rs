// Profile management and persistent storage for Phobos client

use std::fs;
use std::path::{Path, PathBuf};
use crate::archive::PhobosProfile;

/// Returns the persistent directory where profiles are stored
pub fn get_profiles_dir() -> PathBuf {
    let dir = if let Ok(appdata) = std::env::var("APPDATA") {
        PathBuf::from(appdata).join("Phobos").join("profiles")
    } else {
        PathBuf::from("profiles")
    };
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Loads all saved profiles from the profiles directory
pub fn load_all_profiles() -> Vec<PhobosProfile> {
    let dir = get_profiles_dir();
    let mut profiles = Vec::new();

    // Check if store has never been seeded; if so, try to seed once from Downloads
    seed_from_downloads(&dir);

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if ext.eq_ignore_ascii_case("gz") || ext.eq_ignore_ascii_case("tgz") || ext.eq_ignore_ascii_case("conf") {
                    if let Ok(profile) = PhobosProfile::load_from_file(&path) {
                        profiles.push(profile);
                    }
                }
            }
        }
    }

    // Sort alphabetically by client name
    profiles.sort_by(|a, b| a.client_name.to_lowercase().cmp(&b.client_name.to_lowercase()));
    profiles
}

/// Imports a profile file (.tar.gz, .tgz, .conf) into the persistent storage
pub fn import_profile<P: AsRef<Path>>(source_path: P) -> Result<PhobosProfile, String> {
    let source_path = source_path.as_ref();
    if !source_path.exists() {
        return Err(format!("Файл не найден: {}", source_path.display()));
    }

    // Validate that it parses correctly first
    let profile = PhobosProfile::load_from_file(source_path)?;

    // Copy file into profiles directory
    let dir = get_profiles_dir();
    let file_name = source_path.file_name()
        .map(|f| f.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from(format!("{}.tar.gz", profile.client_name)));

    let target_path = dir.join(file_name);
    let _ = fs::copy(source_path, &target_path);

    // Make sure .seeded marker exists so seed_from_downloads never overrides user actions
    let _ = fs::write(dir.join(".seeded"), b"1");

    Ok(profile)
}

/// Deletes a profile by client name from persistent storage
pub fn delete_profile(client_name: &str) -> Result<(), String> {
    let dir = get_profiles_dir();
    let mut found = false;

    // Ensure .seeded marker is written so it won't re-seed on next load!
    let _ = fs::write(dir.join(".seeded"), b"1");

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // 1. Try parsing the profile to match client_name
            if let Ok(profile) = PhobosProfile::load_from_file(&path) {
                if profile.client_name.eq_ignore_ascii_case(client_name) {
                    let _ = fs::remove_file(&path);
                    found = true;
                    continue;
                }
            }

            // 2. Also check file name stem matching
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let clean_stem = stem.trim_end_matches(".tar").trim_start_matches("phobos-");

            if clean_stem.eq_ignore_ascii_case(client_name) || stem.eq_ignore_ascii_case(client_name) {
                let _ = fs::remove_file(&path);
                found = true;
            }
        }
    }

    if found {
        Ok(())
    } else {
        Err(format!("Профиль '{}' не найден", client_name))
    }
}

/// Automatically imports test profile from user's Downloads directory only on very first start
fn seed_from_downloads(target_dir: &Path) {
    let marker = target_dir.join(".seeded");
    if marker.exists() {
        return; // Already initialized once. Never re-seed if user deleted profiles!
    }
    let _ = fs::write(&marker, b"1");

    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let downloads = PathBuf::from(userprofile).join("Downloads");
        if let Ok(entries) = fs::read_dir(downloads) {
            for entry in entries.flatten() {
                let path = entry.path();
                let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if fname.starts_with("phobos-") && (fname.ends_with(".tar.gz") || fname.ends_with(".tgz")) {
                    let _ = fs::copy(&path, target_dir.join(fname));
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_store_dir_and_load() {
        let dir = get_profiles_dir();
        assert!(dir.exists() || fs::create_dir_all(&dir).is_ok());
        let profiles = load_all_profiles();
        println!("Loaded {} profiles", profiles.len());
    }

    #[test]
    fn test_delete_profile() {
        let dir = get_profiles_dir();
        let test_file = dir.join("phobos-testdelete.conf");
        let _ = fs::write(&test_file, b"[Interface]\nPrivateKey = aaaa\nAddress = 10.0.0.1/24\n[Peer]\nPublicKey = bbbb\nEndpoint = 1.1.1.1:51820\n");
        assert!(test_file.exists());
        let res = delete_profile("testdelete");
        assert!(res.is_ok());
        assert!(!test_file.exists());
    }
}
