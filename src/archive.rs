// Archive unpacker and config extractor for Phobos packages

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use flate2::read::GzDecoder;
use tar::Archive;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct PhobosProfile {
    pub client_name: String,
    pub target: String,
    pub key: Vec<u8>,
    pub masking: String,
    pub local_port: u16,
    pub max_dummy: usize,
    pub obfuscate_bytes: usize,
    pub raw_wg_conf: String,
    pub ready_wg_conf_content: String,
    pub ready_wg_conf_path: Option<PathBuf>,
}

impl fmt::Debug for PhobosProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhobosProfile")
            .field("client_name", &self.client_name)
            .field("target", &self.target)
            .field("key", &"[REDACTED]")
            .field("masking", &self.masking)
            .field("local_port", &self.local_port)
            .field("max_dummy", &self.max_dummy)
            .field("obfuscate_bytes", &self.obfuscate_bytes)
            .field("raw_wg_conf", &"[REDACTED]")
            .field("ready_wg_conf_content", &"[REDACTED]")
            .field("ready_wg_conf_path", &self.ready_wg_conf_path)
            .finish()
    }
}

impl Drop for PhobosProfile {
    fn drop(&mut self) {
        self.key.zeroize();
        self.raw_wg_conf.zeroize();
        self.ready_wg_conf_content.zeroize();
    }
}

const MAX_CONF_ENTRY_SIZE: u64 = 1024 * 1024; // 1 MB limit per configuration file to prevent decompression bombs
const MAX_TAR_ENTRIES: usize = 256; // Limit total entries to prevent archive bomb DoS

/// Sanitizes client name to only allow safe filename characters (alphanumeric, -, _, .)
pub fn sanitize_client_name(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();

    let clean = sanitized.trim_matches(|c| c == '.' || c == ' ' || c == '_');
    if clean.is_empty() || clean == ".." {
        "phobos".to_string()
    } else {
        clean.to_string()
    }
}

impl PhobosProfile {
    /// Loads a Phobos profile from a .tar.gz archive, a .conf file, or encrypted DPAPI profile.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(format!("File not found: {}", path.display()));
        }

        let mut raw_bytes = Vec::new();
        let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        file.read_to_end(&mut raw_bytes).map_err(|e| format!("Failed to read file: {}", e))?;

        // Check if file is encrypted with Windows DPAPI
        let bytes = if raw_bytes.starts_with(crate::profile_store::DPAPI_MAGIC) {
            crate::profile_store::dpapi_unprotect(&raw_bytes[crate::profile_store::DPAPI_MAGIC.len()..])?
        } else {
            raw_bytes
        };

        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
        let name_hint = path.file_stem().and_then(|s| s.to_str()).unwrap_or("phobos");

        // 1. Try as tar.gz
        let cursor = std::io::Cursor::new(&bytes);
        if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") || filename.ends_with(".enc") {
            if let Ok(profile) = Self::load_from_tar_gz(cursor, path) {
                return Ok(profile);
            }
        }

        // 2. Try as UTF-8 conf string
        if let Ok(content) = std::str::from_utf8(&bytes) {
            if let Ok(profile) = Self::load_from_conf_string(content, name_hint) {
                return Ok(profile);
            }
        }

        // 3. Fallback: try tar.gz anyway, then conf string
        let cursor = std::io::Cursor::new(&bytes);
        match Self::load_from_tar_gz(cursor, path) {
            Ok(profile) => Ok(profile),
            Err(_) => {
                let content = std::str::from_utf8(&bytes)
                    .map_err(|e| format!("File is neither valid tar.gz nor valid UTF-8 conf: {}", e))?;
                Self::load_from_conf_string(content, name_hint)
            }
        }
    }

    /// Loads directly from a .tar.gz stream
    pub fn load_from_tar_gz<R: Read>(reader: R, original_path: &Path) -> Result<Self, String> {
        let gz = GzDecoder::new(reader);
        let mut archive = Archive::new(gz);

        let mut wg_conf_content: Option<String> = None;
        let mut obf_conf_content: Option<String> = None;
        let mut client_name = original_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("phobos")
            .trim_end_matches(".tar")
            .to_string();

        if client_name.starts_with("phobos-") {
            client_name = client_name["phobos-".len()..].to_string();
        }

        let entries = archive
            .entries()
            .map_err(|e| format!("Failed to read tar.gz entries: {}", e))?;

        let mut entry_count = 0;
        for entry in entries {
            entry_count += 1;
            if entry_count > MAX_TAR_ENTRIES {
                return Err(format!("Archive contains too many entries (exceeds limit of {})", MAX_TAR_ENTRIES));
            }
            let mut entry = entry.map_err(|e| format!("Corrupted tar entry: {}", e))?;
            let path = entry.path().map_err(|e| format!("Invalid tar path: {}", e))?.to_path_buf();
            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

            if fname == "wg-obfuscator.conf" {
                let mut s = String::new();
                entry.by_ref().take(MAX_CONF_ENTRY_SIZE).read_to_string(&mut s)
                    .map_err(|e| format!("Failed to read wg-obfuscator.conf: {}", e))?;
                obf_conf_content = Some(s);
            } else if fname.ends_with(".conf") {
                let mut s = String::new();
                entry.by_ref().take(MAX_CONF_ENTRY_SIZE).read_to_string(&mut s)
                    .map_err(|e| format!("Failed to read {}: {}", fname, e))?;
                wg_conf_content = Some(s);
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if !stem.is_empty() && stem != "wg-obfuscator" {
                    client_name = stem.to_string();
                }
            }
        }

        let obf_conf = obf_conf_content.ok_or_else(|| {
            "wg-obfuscator.conf not found inside tar.gz archive. Is this a Phobos package?".to_string()
        })?;

        let wg_conf = wg_conf_content.ok_or_else(|| {
            "WireGuard .conf file not found inside tar.gz archive.".to_string()
        })?;

        Self::combine_and_build(&wg_conf, &obf_conf, &client_name)
    }

    /// Loads from a single merged configuration string (e.g. from phobos:// link or exported conf)
    pub fn load_from_conf_string(content: &str, client_name: &str) -> Result<Self, String> {
        let (wg_conf, obf_conf) = split_merged_conf(content);
        Self::combine_and_build(&wg_conf, &obf_conf, client_name)
    }

    fn combine_and_build(wg_conf_raw: &str, obf_conf_raw: &str, client_name: &str) -> Result<Self, String> {
        let obf_params = parse_instance_section(obf_conf_raw);

        let target = obf_params
            .get("target")
            .cloned()
            .ok_or_else(|| "Missing 'target' in obfuscator configuration".to_string())?;

        let key_str = obf_params
            .get("key")
            .cloned()
            .ok_or_else(|| "Missing 'key' in obfuscator configuration".to_string())?;

        if key_str.len() < 8 {
            eprintln!(
                "[!] Предупреждение: Ключ обфускации очень короткий ({} байт). Рекомендуется минимум 8-16 символов.",
                key_str.len()
            );
        }

        let masking = obf_params
            .get("masking")
            .map(|s| s.to_uppercase())
            .unwrap_or_else(|| "STUN".to_string());

        let local_port: u16 = obf_params
            .get("source-lport")
            .and_then(|s| s.parse().ok())
            .unwrap_or(13255);

        let max_dummy: usize = obf_params
            .get("max-dummy")
            .and_then(|s| s.parse().ok())
            .unwrap_or(crate::obfuscator::DEFAULT_MAX_DUMMY);

        let obfuscate_bytes: usize = obf_params
            .get("obfuscate-bytes")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Adjust the WireGuard client configuration so Endpoint points to loopback:
        let ready_wg_conf = rewrite_endpoint_to_loopback(wg_conf_raw, local_port);
        let safe_name = sanitize_client_name(client_name);

        Ok(Self {
            client_name: safe_name,
            target,
            key: key_str.into_bytes(),
            masking,
            local_port,
            max_dummy,
            obfuscate_bytes,
            raw_wg_conf: wg_conf_raw.to_string(),
            ready_wg_conf_content: ready_wg_conf,
            ready_wg_conf_path: None,
        })
    }

    /// Parses the underlying WireGuard configuration into structured parameters
    pub fn parse_wg_config(&self) -> Result<crate::wg_config::WireGuardConfig, String> {
        crate::wg_config::WireGuardConfig::parse(&self.raw_wg_conf)
    }

    /// Saves the generated ready-to-import WireGuard .conf file
    pub fn export_ready_wg_conf<P: AsRef<Path>>(&mut self, output_dir: P) -> Result<PathBuf, String> {
        let safe_name = sanitize_client_name(&self.client_name);
        let path = output_dir.as_ref().join(format!("{}-ready.conf", safe_name));
        std::fs::write(&path, &self.ready_wg_conf_content)
            .map_err(|e| format!("Failed to write ready WireGuard config to {}: {}", path.display(), e))?;

        // Restrict file ACL so only current user / owner and administrators can read private key
        if let Err(e) = crate::windows_net::set_file_owner_only_acl(&path) {
            eprintln!("[!] Предупреждение безопасности: не удалось ограничить ACL файла конфигурации {}: {}", path.display(), e);
        }

        self.ready_wg_conf_path = Some(path.clone());
        Ok(path)
    }
}

/// Parses key=value pairs inside [instance] section
fn parse_instance_section(conf: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut in_instance = false;

    for line in conf.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = &trimmed[1..trimmed.len() - 1].trim();
            in_instance = section.eq_ignore_ascii_case("instance");
            continue;
        }

        if in_instance {
            if let Some((k, v)) = trimmed.split_once('=') {
                let k = k.trim().to_lowercase();
                let v = v.trim();
                map.insert(k, v.to_string());
            }
        }
    }

    // If there was no [instance] header, but there are keys like target= or key=, parse them too:
    if map.is_empty() {
        for line in conf.lines() {
            let trimmed = line.trim();
            if let Some((k, v)) = trimmed.split_once('=') {
                let k = k.trim().to_lowercase();
                let v = v.trim();
                if ["target", "key", "masking", "source-lport", "max-dummy", "obfuscate-bytes"].contains(&k.as_str()) {
                    map.insert(k, v.to_string());
                }
            }
        }
    }

    map
}

/// Splits a combined configuration file containing both WireGuard sections and [instance]
fn split_merged_conf(conf: &str) -> (String, String) {
    let mut wg_lines = Vec::new();
    let mut obf_lines = Vec::new();
    let mut in_instance = false;

    for line in conf.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let sec = &trimmed[1..trimmed.len() - 1].trim();
            in_instance = sec.eq_ignore_ascii_case("instance") || sec.eq_ignore_ascii_case("socks5");
        }

        if in_instance {
            obf_lines.push(line);
        } else {
            wg_lines.push(line);
        }
    }

    (wg_lines.join("\n"), obf_lines.join("\n"))
}

/// Updates the Endpoint in [Peer] to point to 127.0.0.1:<local_port>, sets MTU to 1280,
/// and rewrites 0.0.0.0/0 to avoid WireGuard's aggressive Windows WFP kill-switch.
fn rewrite_endpoint_to_loopback(conf: &str, local_port: u16) -> String {
    let mut out = Vec::new();
    let mut endpoint_seen = false;
    let mut mtu_seen = false;
    let mut in_interface = false;
    let mut in_peer = false;

    for line in conf.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let sec = &trimmed[1..trimmed.len() - 1].trim();
            if in_interface && !mtu_seen {
                out.push("MTU = 1280".to_string());
            }
            if in_peer && !endpoint_seen {
                out.push(format!("Endpoint = 127.0.0.1:{}", local_port));
            }
            in_interface = sec.eq_ignore_ascii_case("interface");
            in_peer = sec.eq_ignore_ascii_case("peer");
            endpoint_seen = false;
            mtu_seen = false;
            out.push(line.to_string());
            continue;
        }

        if in_interface && trimmed.to_lowercase().starts_with("mtu") {
            // Lower MTU to 1280 to prevent PMTU black holes with STUN and dummy padding
            out.push("MTU = 1280".to_string());
            mtu_seen = true;
            continue;
        }

        if in_peer && trimmed.to_lowercase().starts_with("endpoint") {
            out.push(format!("Endpoint = 127.0.0.1:{}", local_port));
            endpoint_seen = true;
            continue;
        }

        if in_peer && trimmed.to_lowercase().starts_with("allowedips") {
            // Replace 0.0.0.0/0 with 0.0.0.0/1, 128.0.0.0/1 and ::/0 with ::/1, 8000::/1
            // This routes ALL traffic through WireGuard without triggering the WFP kill-switch
            // that blocks untunneled UDP traffic to local proxy relays.
            let new_line = line
                .replace("0.0.0.0/0", "0.0.0.0/1, 128.0.0.0/1")
                .replace("::/0", "::/1, 8000::/1");
            out.push(new_line);
            continue;
        }

        out.push(line.to_string());
    }

    if in_interface && !mtu_seen {
        out.push("MTU = 1280".to_string());
    }
    if in_peer && !endpoint_seen {
        out.push(format!("Endpoint = 127.0.0.1:{}", local_port));
    }

    out.join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_instance_and_rewrite() {
        let wg = r#"[Interface]
PrivateKey = aaaaa=
Address = 10.8.0.2/32

[Peer]
PublicKey = bbbbb=
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
"#;

        let obf = r#"[instance]
target = 130.49.185.136:51824
key = SecretKey123
masking = STUN
source-lport = 13255
max-dummy = 45
"#;

        let profile = PhobosProfile::combine_and_build(wg, obf, "test-client").unwrap();
        assert_eq!(profile.target, "130.49.185.136:51824");
        assert_eq!(profile.key, b"SecretKey123");
        assert_eq!(profile.masking, "STUN");
        assert_eq!(profile.local_port, 13255);
        assert_eq!(profile.max_dummy, 45);

        assert!(profile.ready_wg_conf_content.contains("Endpoint = 127.0.0.1:13255"));
        assert!(!profile.ready_wg_conf_content.contains("Endpoint = 1.2.3.4:51820"));
    }

    #[test]
    fn test_load_from_tar_gz_archive() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::Builder;

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = Builder::new(&mut gz);

            let wg_data = b"[Interface]\nPrivateKey = aaaaa=\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = bbbbb=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n";
            let mut header_wg = tar::Header::new_gnu();
            header_wg.set_path("phobos-myphone/myphone.conf").unwrap();
            header_wg.set_size(wg_data.len() as u64);
            header_wg.set_mode(0o600);
            header_wg.set_cksum();
            tar.append(&header_wg, &wg_data[..]).unwrap();

            let obf_data = b"[instance]\ntarget = vpn.example.com:51830\nkey = MySecretKey\nmasking = STUN\nsource-lport = 13255\nmax-dummy = 20\n";
            let mut header_obf = tar::Header::new_gnu();
            header_obf.set_path("phobos-myphone/wg-obfuscator.conf").unwrap();
            header_obf.set_size(obf_data.len() as u64);
            header_obf.set_mode(0o600);
            header_obf.set_cksum();
            tar.append(&header_obf, &obf_data[..]).unwrap();

            tar.finish().unwrap();
        }
        let compressed = gz.finish().unwrap();

        let cursor = std::io::Cursor::new(compressed);
        let profile = PhobosProfile::load_from_tar_gz(cursor, Path::new("phobos-myphone.tar.gz")).expect("must parse tar.gz");

        assert_eq!(profile.client_name, "myphone");
        assert_eq!(profile.target, "vpn.example.com:51830");
        assert_eq!(profile.key, b"MySecretKey");
        assert_eq!(profile.masking, "STUN");
        assert_eq!(profile.local_port, 13255);
        assert_eq!(profile.max_dummy, 20);
        assert!(profile.ready_wg_conf_content.contains("Endpoint = 127.0.0.1:13255"));
    }

    #[test]
    fn test_sanitize_client_name() {
        assert_eq!(sanitize_client_name("../../etc/passwd"), "etc_passwd");
        assert_eq!(sanitize_client_name(r"..\..\Windows\System32"), "Windows_System32");
        assert_eq!(sanitize_client_name(".."), "phobos");
        assert_eq!(sanitize_client_name("valid-client.1"), "valid-client.1");
        assert_eq!(sanitize_client_name("   "), "phobos");
    }

    #[test]
    fn test_profile_debug_redaction() {
        let profile = PhobosProfile {
            client_name: "test-user".to_string(),
            target: "1.2.3.4:51820".to_string(),
            key: b"SuperSecretObfuscationKey".to_vec(),
            masking: "STUN".to_string(),
            local_port: 13255,
            max_dummy: 4,
            obfuscate_bytes: 0,
            raw_wg_conf: "PrivateKey = SecretPrivateKeyBase64Here".to_string(),
            ready_wg_conf_content: "PrivateKey = SecretPrivateKeyBase64Here".to_string(),
            ready_wg_conf_path: None,
        };

        let debug_str = format!("{:?}", profile);
        assert!(!debug_str.contains("SuperSecretObfuscationKey"), "Debug output must not contain obfuscation key");
        assert!(!debug_str.contains("SecretPrivateKeyBase64Here"), "Debug output must not contain WireGuard configuration");
        assert!(debug_str.contains("[REDACTED]"), "Debug output must contain [REDACTED]");
    }
}
