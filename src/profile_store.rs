// Profile management and persistent storage for Phobos client
//
// SECURITY NOTICE:
// Profiles contain sensitive WireGuard PrivateKeys and obfuscation keys.
// In persistent storage, profiles are protected at rest using Windows DPAPI
// (Data Protection API), which encrypts secrets using keys derived from the
// Windows logon credentials of the current user.

use std::fs;
use std::path::{Path, PathBuf};
use crate::archive::PhobosProfile;

pub const DPAPI_MAGIC: &[u8] = b"PHOBOS_DPAPI_V1\0";

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
struct CRYPTOAPI_BLOB {
    cbData: u32,
    pbData: *mut u8,
}

#[cfg(windows)]
#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        pDataIn: *const CRYPTOAPI_BLOB,
        szDataDescr: *const u16,
        pOptionalEntropy: *const CRYPTOAPI_BLOB,
        pvReserved: *mut std::ffi::c_void,
        pPromptStruct: *mut std::ffi::c_void,
        dwFlags: u32,
        pDataOut: *mut CRYPTOAPI_BLOB,
    ) -> i32;

    fn CryptUnprotectData(
        pDataIn: *const CRYPTOAPI_BLOB,
        ppszDataDescr: *mut *mut u16,
        pOptionalEntropy: *const CRYPTOAPI_BLOB,
        pvReserved: *mut std::ffi::c_void,
        pPromptStruct: *mut std::ffi::c_void,
        dwFlags: u32,
        pDataOut: *mut CRYPTOAPI_BLOB,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

/// Encrypts data at rest using Windows DPAPI tied to current user logon credentials
#[cfg(windows)]
pub fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.is_empty() {
        return Ok(Vec::new());
    }

    let mut data_in = CRYPTOAPI_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPTOAPI_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let descr: Vec<u16> = "PhobosProfile\0".encode_utf16().collect();

    let success = unsafe {
        CryptProtectData(
            &mut data_in,
            descr.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut data_out,
        )
    };

    if success == 0 {
        return Err("CryptProtectData failed to encrypt profile data".to_string());
    }

    let result = unsafe {
        let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(data_out.pbData as _);
        vec
    };

    Ok(result)
}

#[cfg(not(windows))]
pub fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    eprintln!("[!] Предупреждение безопасности: DPAPI поддерживается только на Windows. Профиль сохраняется в открытом виде.");
    Ok(plaintext.to_vec())
}

/// Decrypts data at rest using Windows DPAPI
#[cfg(windows)]
pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }

    let mut data_in = CRYPTOAPI_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPTOAPI_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let success = unsafe {
        CryptUnprotectData(
            &mut data_in,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut data_out,
        )
    };

    if success == 0 {
        return Err("CryptUnprotectData failed to decrypt profile data (was it created by another user?)".to_string());
    }

    let result = unsafe {
        let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(data_out.pbData as _);
        vec
    };

    Ok(result)
}

#[cfg(not(windows))]
pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    Ok(ciphertext.to_vec())
}

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

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if ext.eq_ignore_ascii_case("enc")
                    || ext.eq_ignore_ascii_case("gz")
                    || ext.eq_ignore_ascii_case("tgz")
                    || ext.eq_ignore_ascii_case("conf")
                {
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

/// Checks if the file path has a supported profile extension (.tar.gz, .tgz, .conf, .enc)
pub fn is_supported_profile_path<P: AsRef<Path>>(path: P) -> bool {
    let p = path.as_ref();
    let filename = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    filename.ends_with(".tar.gz")
        || filename.ends_with(".tgz")
        || filename.ends_with(".conf")
        || filename.ends_with(".enc")
}

/// Imports a profile file into persistent storage, encrypting it with DPAPI
pub fn import_profile<P: AsRef<Path>>(source_path: P) -> Result<PhobosProfile, String> {
    let source_path = source_path.as_ref();
    if !source_path.exists() || !source_path.is_file() {
        return Err(format!("Файл не найден или не является обычным файлом: {}", source_path.display()));
    }

    if !is_supported_profile_path(source_path) {
        return Err(format!(
            "Неподдерживаемый формат файла: {}. Поддерживаются .tar.gz, .tgz, .conf, .enc",
            source_path.display()
        ));
    }

    // Validate that it parses correctly first
    let profile = PhobosProfile::load_from_file(source_path)?;

    // Read original raw file bytes
    let raw_bytes = fs::read(source_path)
        .map_err(|e| format!("Не удалось прочитать исходный файл профиля: {}", e))?;

    // Protect payload at rest with Windows DPAPI
    let payload = if raw_bytes.starts_with(DPAPI_MAGIC) {
        raw_bytes
    } else {
        let mut protected = Vec::from(DPAPI_MAGIC);
        let enc = dpapi_protect(&raw_bytes)?;
        protected.extend_from_slice(&enc);
        protected
    };

    let dir = get_profiles_dir();
    let safe_stem = crate::archive::sanitize_client_name(&profile.client_name);
    let target_path = dir.join(format!("{}.enc", safe_stem));

    fs::write(&target_path, &payload)
        .map_err(|e| format!("Не удалось сохранить зашифрованный профиль: {}", e))?;

    // Restrict permissions on encrypted profile at rest
    let _ = crate::windows_net::set_file_owner_only_acl(&target_path);

    Ok(profile)
}

/// Deletes a profile by client name from persistent storage
pub fn delete_profile(client_name: &str) -> Result<(), String> {
    let dir = get_profiles_dir();
    let mut found = false;

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // 1. Try parsing the profile to match client_name
            let matches = if let Ok(profile) = PhobosProfile::load_from_file(&path) {
                profile.client_name.eq_ignore_ascii_case(client_name)
            } else {
                // 2. Fallback check file name stem
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let clean_stem = stem.trim_end_matches(".tar").trim_start_matches("phobos-");
                clean_stem.eq_ignore_ascii_case(client_name) || stem.eq_ignore_ascii_case(client_name)
            };

            if matches {
                fs::remove_file(&path)
                    .map_err(|e| format!("Не удалось удалить файл профиля '{}': {}", path.display(), e))?;
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

    #[test]
    fn test_dpapi_roundtrip() {
        let secret_data = b"PrivateKey = SecretKeyHere123456";
        let encrypted = dpapi_protect(secret_data).expect("DPAPI protect must succeed");
        #[cfg(windows)]
        assert_ne!(&encrypted, secret_data, "Ciphertext must not match plaintext");
        let decrypted = dpapi_unprotect(&encrypted).expect("DPAPI unprotect must succeed");
        assert_eq!(&decrypted, secret_data, "Decrypted data must match original plaintext");
    }

    #[test]
    fn test_is_supported_profile_path() {
        assert!(is_supported_profile_path(Path::new("client.conf")));
        assert!(is_supported_profile_path(Path::new("package.tar.gz")));
        assert!(is_supported_profile_path(Path::new("package.tgz")));
        assert!(is_supported_profile_path(Path::new("profile.enc")));
        assert!(!is_supported_profile_path(Path::new("malicious.exe")));
        assert!(!is_supported_profile_path(Path::new("document.pdf")));
        assert!(!is_supported_profile_path(Path::new("script.bat")));
    }
}
