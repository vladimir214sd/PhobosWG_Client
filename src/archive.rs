// Archive unpacker and config extractor for Phobos packages

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use flate2::read::GzDecoder;
use tar::Archive;

#[derive(Debug, Clone)]
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

impl PhobosProfile {
    /// Loads a Phobos profile from a .tar.gz archive, a .conf file, or raw data.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(format!("File not found: {}", path.display()));
        }

        let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

        if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
            Self::load_from_tar_gz(file, path)
        } else if filename.ends_with(".conf") {
            let mut content = String::new();
            let mut file = file;
            file.read_to_string(&mut content)
                .map_err(|e| format!("Failed to read .conf file: {}", e))?;
            Self::load_from_conf_string(&content, path.file_stem().and_then(|s| s.to_str()).unwrap_or("phobos"))
        } else {
            // Try tar.gz first, if fail try text
            match Self::load_from_tar_gz(file, path) {
                Ok(profile) => Ok(profile),
                Err(_) => {
                    let mut content = String::new();
                    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
                    file.read_to_string(&mut content)
                        .map_err(|e| format!("File is not a valid tar.gz or text conf: {}", e))?;
                    Self::load_from_conf_string(&content, "phobos")
                }
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

        for entry in entries {
            let mut entry = entry.map_err(|e| format!("Corrupted tar entry: {}", e))?;
            let path = entry.path().map_err(|e| format!("Invalid tar path: {}", e))?.to_path_buf();
            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();

            if fname == "wg-obfuscator.conf" {
                let mut s = String::new();
                entry.read_to_string(&mut s).map_err(|e| format!("Failed to read wg-obfuscator.conf: {}", e))?;
                obf_conf_content = Some(s);
            } else if fname.ends_with(".conf") {
                let mut s = String::new();
                entry.read_to_string(&mut s).map_err(|e| format!("Failed to read {}: {}", fname, e))?;
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

        Ok(Self {
            client_name: client_name.to_string(),
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
        let path = output_dir.as_ref().join(format!("{}-ready.conf", self.client_name));
        std::fs::write(&path, &self.ready_wg_conf_content)
            .map_err(|e| format!("Failed to write ready WireGuard config to {}: {}", path.display(), e))?;
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
            // that blocks untunneled UDP traffic to companion proxies.
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
}
