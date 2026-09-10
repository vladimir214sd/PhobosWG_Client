use std::fmt;
use std::net::IpAddr;
use base64::Engine;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct WireGuardConfig {
    pub private_key: [u8; 32],
    pub client_ipv4: std::net::Ipv4Addr,
    pub client_ipv4_prefix: u8,
    pub client_ipv6: Option<std::net::Ipv6Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: usize,
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    pub allowed_ips: Vec<String>,
}

impl fmt::Debug for WireGuardConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardConfig")
            .field("private_key", &"[REDACTED]")
            .field("client_ipv4", &self.client_ipv4)
            .field("client_ipv4_prefix", &self.client_ipv4_prefix)
            .field("client_ipv6", &self.client_ipv6)
            .field("dns_servers", &self.dns_servers)
            .field("mtu", &self.mtu)
            .field("peer_public_key", &self.peer_public_key)
            .field("preshared_key", &self.preshared_key.as_ref().map(|_| "[REDACTED]"))
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("allowed_ips", &self.allowed_ips)
            .finish()
    }
}

impl Drop for WireGuardConfig {
    fn drop(&mut self) {
        self.private_key.zeroize();
        if let Some(ref mut psk) = self.preshared_key {
            psk.zeroize();
        }
    }
}

impl WireGuardConfig {
    /// Parses a standard WireGuard .conf content
    pub fn parse(conf: &str) -> Result<Self, String> {
        let mut private_key = None;
        let mut client_ipv4 = None;
        let mut client_ipv4_prefix = 32u8;
        let mut client_ipv6 = None;
        let mut dns_servers = Vec::new();
        let mut mtu = 1280; // Safe default for Phobos with STUN & dummy bytes
        let mut peer_public_key = None;
        let mut preshared_key = None;
        let mut persistent_keepalive = None;
        let mut allowed_ips = Vec::new();

        let mut in_interface = false;
        let mut in_peer = false;

        for line in conf.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
                continue;
            }

            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let sec = &trimmed[1..trimmed.len() - 1].trim();
                in_interface = sec.eq_ignore_ascii_case("interface");
                in_peer = sec.eq_ignore_ascii_case("peer");
                continue;
            }

            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim().to_lowercase();
                let val = v.trim();

                if in_interface {
                    match key.as_str() {
                        "privatekey" => {
                            let bytes = decode_key_32(val)
                                .map_err(|e| format!("Invalid PrivateKey in [Interface]: {}", e))?;
                            private_key = Some(bytes);
                        }
                        "address" => {
                            // Multiple addresses can be comma-separated
                            for part in val.split(',') {
                                let part = part.trim();
                                if let Some((ip_str, prefix_str)) = part.split_once('/') {
                                    let prefix: u8 = prefix_str.parse().unwrap_or(32);
                                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                        match ip {
                                            IpAddr::V4(v4) => {
                                                if client_ipv4.is_none() {
                                                    client_ipv4 = Some(v4);
                                                    client_ipv4_prefix = prefix;
                                                }
                                            }
                                            IpAddr::V6(v6) => {
                                                if client_ipv6.is_none() {
                                                    client_ipv6 = Some(v6);
                                                }
                                            }
                                        }
                                    }
                                } else if let Ok(ip) = part.parse::<IpAddr>() {
                                    match ip {
                                        IpAddr::V4(v4) => {
                                            if client_ipv4.is_none() {
                                                client_ipv4 = Some(v4);
                                            }
                                        }
                                        IpAddr::V6(v6) => {
                                            if client_ipv6.is_none() {
                                                client_ipv6 = Some(v6);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        "dns" => {
                            for part in val.split(',') {
                                if let Ok(ip) = part.trim().parse::<IpAddr>() {
                                    dns_servers.push(ip);
                                }
                            }
                        }
                        "mtu" => {
                            if let Ok(m) = val.parse::<usize>() {
                                // Clamp MTU to at most 1280 to prevent black holes with Phobos overhead
                                mtu = m.min(1280);
                            }
                        }
                        _ => {}
                    }
                } else if in_peer {
                    match key.as_str() {
                        "publickey" => {
                            let bytes = decode_key_32(val)
                                .map_err(|e| format!("Invalid PublicKey in [Peer]: {}", e))?;
                            peer_public_key = Some(bytes);
                        }
                        "presharedkey" => {
                            let bytes = decode_key_32(val)
                                .map_err(|e| format!("Invalid PresharedKey in [Peer]: {}", e))?;
                            preshared_key = Some(bytes);
                        }
                        "allowedips" => {
                            for part in val.split(',') {
                                allowed_ips.push(part.trim().to_string());
                            }
                        }
                        "persistentkeepalive" => {
                            if let Ok(pk) = val.parse::<u16>() {
                                if pk > 0 {
                                    persistent_keepalive = Some(pk);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let private_key = private_key.ok_or_else(|| "Missing PrivateKey in [Interface]".to_string())?;
        let peer_public_key = peer_public_key.ok_or_else(|| "Missing PublicKey in [Peer]".to_string())?;
        let client_ipv4 = client_ipv4.ok_or_else(|| "Missing IPv4 Address in [Interface]".to_string())?;

        if dns_servers.is_empty() {
            // Default to Cloudflare & Google DNS if none specified
            dns_servers.push(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
            dns_servers.push(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)));
        }

        Ok(Self {
            private_key,
            client_ipv4,
            client_ipv4_prefix,
            client_ipv6,
            dns_servers,
            mtu,
            peer_public_key,
            preshared_key,
            persistent_keepalive,
            allowed_ips,
        })
    }
}

fn decode_key_32(val: &str) -> Result<[u8; 32], String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(val.trim())
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes key, got {} bytes", bytes.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wireguard_conf() {
        let conf = r#"
[Interface]
PrivateKey = MCKqsOSxkbsMPFY4NwOstrz6LxZCJHVmZHbfpzukK2k=
Address = 10.8.0.3/32, fdcc:ad94:bacf:61a4::cafe:3/128
MTU = 1420
DNS = 8.8.8.8, 2001:4860:4860::8888

[Peer]
PublicKey = fW0sRjGeNpq2ZM+gSftFitWbEMVP5YItK8Qq2TesyBs=
PresharedKey = 9ai9fEt+ejoo4DttV3/GnSQU8DLEGZli1fiTS927DGI=
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
Endpoint = 127.0.0.1:13255
"#;

        let wg = WireGuardConfig::parse(conf).unwrap();
        assert_eq!(wg.client_ipv4, std::net::Ipv4Addr::new(10, 8, 0, 3));
        assert_eq!(wg.client_ipv4_prefix, 32);
        assert_eq!(wg.mtu, 1280); // Clamped from 1420 to 1280!
        assert_eq!(wg.dns_servers.len(), 2);
        assert_eq!(wg.persistent_keepalive, Some(25));
        assert!(wg.preshared_key.is_some());
    }

    #[test]
    fn test_debug_redaction() {
        let conf = r#"
[Interface]
PrivateKey = MCKqsOSxkbsMPFY4NwOstrz6LxZCJHVmZHbfpzukK2k=
Address = 10.8.0.3/32
[Peer]
PublicKey = fW0sRjGeNpq2ZM+gSftFitWbEMVP5YItK8Qq2TesyBs=
PresharedKey = 9ai9fEt+ejoo4DttV3/GnSQU8DLEGZli1fiTS927DGI=
"#;
        let wg = WireGuardConfig::parse(conf).unwrap();
        let debug_str = format!("{:?}", wg);
        assert!(!debug_str.contains("MCKqsOSxkbs"), "Debug output must not contain raw private key");
        assert!(debug_str.contains("[REDACTED]"), "Debug output must contain [REDACTED]");
    }
}
