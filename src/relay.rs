// High-performance UDP relay for Phobos WireGuard obfuscation

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::archive::PhobosProfile;
use crate::obfuscator::{Obfuscator, TYPE_HANDSHAKE};
use crate::stun::{
    is_stun_packet, stun_build_binding_request, stun_message_type,
    stun_unwrap_data_indication, stun_wrap_data_indication, STUN_BINDING_RESP,
};
use crate::windows_net::bind_socket_to_physical_interface;

#[derive(Default)]
pub struct RelayStats {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub pkts_up: AtomicU64,
    pub pkts_down: AtomicU64,
}

pub struct PhobosRelay {
    profile: Arc<PhobosProfile>,
    running: Arc<AtomicBool>,
    pub stats: Arc<RelayStats>,
}

impl PhobosRelay {
    pub fn new(profile: Arc<PhobosProfile>) -> Self {
        Self {
            profile,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(RelayStats::default()),
        }
    }

    pub fn start(&self) -> Result<(), String> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let local_addr = format!("127.0.0.1:{}", self.profile.local_port);
        let listener = UdpSocket::bind(&local_addr)
            .map_err(|e| format!("Failed to bind loopback UDP socket on {}: {}", local_addr, e))?;

        println!("[+] Local relay listening on {}", local_addr);

        // Resolve remote target
        let target_addrs: Vec<SocketAddr> = self.profile.target.to_socket_addrs()
            .map_err(|e| format!("Failed to resolve target '{}': {}", self.profile.target, e))?
            .collect();

        if target_addrs.is_empty() {
            return Err(format!("Could not resolve target address: {}", self.profile.target));
        }
        let target_addr = target_addrs[0];
        println!("[+] Target server resolved to {}", target_addr);

        // Upstream socket
        let upstream = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind upstream socket: {}", e))?;

        // Disable WSAECONNRESET on Windows when receiving ICMP port unreachable
        crate::windows_net::disable_udp_connreset(&upstream);

        // Bypass WireGuard default routing loop on Windows
        match bind_socket_to_physical_interface(&upstream, &target_addr) {
            Ok(if_idx) => {
                println!("[+] Upstream socket bound to physical interface index {} (routing loop protected)", if_idx);
            }
            Err(err) => {
                eprintln!("[!] Warning: Could not bind upstream socket to interface index: {}. (Traffic might route into VPN if AllowedIPs includes server IP)", err);
            }
        }

        upstream.connect(target_addr)
            .map_err(|e| format!("Failed to connect upstream socket to {}: {}", target_addr, e))?;

        let _ = listener.set_read_timeout(Some(Duration::from_millis(250)));
        let _ = upstream.set_read_timeout(Some(Duration::from_millis(250)));

        let obfuscator = Obfuscator::new(
            self.profile.key.clone(),
            self.profile.max_dummy,
            self.profile.obfuscate_bytes,
        );

        let is_stun = self.profile.masking.eq_ignore_ascii_case("STUN");
        println!("[+] Obfuscation active: masking={}, max_dummy={}, key_len={}", 
            self.profile.masking, self.profile.max_dummy, self.profile.key.len());

        let client_addr = Arc::new(Mutex::new(None::<SocketAddr>));

        // Clone sockets for separate threads
        let listener_rx = listener.try_clone().map_err(|e| e.to_string())?;
        let upstream_tx = upstream.try_clone().map_err(|e| e.to_string())?;
        let upstream_ping = upstream.try_clone().map_err(|e| e.to_string())?;

        let listener_tx = listener;
        let upstream_rx = upstream;

        let stats_client = self.stats.clone();
        let running_client = running.clone();
        let obf_client = obfuscator.clone();
        let client_addr_c = client_addr.clone();

        // 1. Client Loop: reads from 127.0.0.1 (WireGuard client), encodes, sends to server
        thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            let mut last_error_log = Instant::now().checked_sub(Duration::from_secs(10)).unwrap_or_else(Instant::now);
            while running_client.load(Ordering::Relaxed) {
                match listener_rx.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if n < 4 {
                            continue;
                        }

                        let pkt_type = Obfuscator::packet_type(&buf[..n]);
                        if let Some(t) = pkt_type {
                            if !Obfuscator::is_known_packet_type(t) {
                                continue;
                            }
                        } else {
                            continue;
                        }

                        // Protect against local relay hijacking (CWE-284):
                        // Bind to the first valid client endpoint and only allow re-binding
                        // if a new Handshake is initiated (e.g. client reconnected).
                        {
                            let mut lock = client_addr_c.lock().unwrap();
                            match *lock {
                                None => {
                                    *lock = Some(src);
                                }
                                Some(current_src) => {
                                    if current_src != src {
                                        if pkt_type == Some(TYPE_HANDSHAKE) {
                                            *lock = Some(src);
                                        } else {
                                            // Reject foreign packet from unauthorized local port
                                            continue;
                                        }
                                    }
                                }
                            }
                        }

                        // On Handshake: if STUN is enabled, send STUN Binding Request first
                        if is_stun && pkt_type == Some(TYPE_HANDSHAKE) {
                            let bind_req = stun_build_binding_request();
                            let _ = upstream_tx.send(&bind_req);
                        }

                        let mut packet = buf[..n].to_vec();
                        obf_client.encode(&mut packet);

                        let final_packet = if is_stun {
                            match stun_wrap_data_indication(&packet) {
                                Some(p) => p,
                                None => packet,
                            }
                        } else {
                            packet
                        };

                        if let Ok(sent) = upstream_tx.send(&final_packet) {
                            stats_client.bytes_up.fetch_add(sent as u64, Ordering::Relaxed);
                            stats_client.pkts_up.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
                            continue;
                        }
                        if running_client.load(Ordering::Relaxed) {
                            if last_error_log.elapsed() >= Duration::from_secs(3) {
                                last_error_log = Instant::now();
                                eprintln!("[!] Client recv error: {}", e);
                            }
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            }
        });

        // 2. Server Loop: reads from server, unwraps, decodes, sends to 127.0.0.1
        let stats_server = self.stats.clone();
        let running_server = running.clone();
        let obf_server = obfuscator;
        let client_addr_s = client_addr;

        thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            let mut last_error_log = Instant::now().checked_sub(Duration::from_secs(10)).unwrap_or_else(Instant::now);
            while running_server.load(Ordering::Relaxed) {
                match upstream_rx.recv(&mut buf) {
                    Ok(n) => {
                        if n == 0 {
                            continue;
                        }

                        stats_server.pkts_down.fetch_add(1, Ordering::Relaxed);
                        stats_server.bytes_down.fetch_add(n as u64, Ordering::Relaxed);

                        let mut payload = if is_stun {
                            if is_stun_packet(&buf[..n]) {
                                if let Some(msg_type) = stun_message_type(&buf[..n]) {
                                    if msg_type == STUN_BINDING_RESP {
                                        // Server responded to STUN keepalive ping
                                        continue;
                                    }
                                }
                                match stun_unwrap_data_indication(&buf[..n]) {
                                    Some(data) => data.to_vec(),
                                    None => continue,
                                }
                            } else {
                                continue;
                            }
                        } else {
                            buf[..n].to_vec()
                        };

                        if obf_server.decode(&mut payload) {
                            let maybe_client = {
                                let lock = client_addr_s.lock().unwrap();
                                *lock
                            };

                            if let Some(c_addr) = maybe_client {
                                let _ = listener_tx.send_to(&payload, c_addr);
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
                            continue;
                        }
                        if running_server.load(Ordering::Relaxed) {
                            let raw = e.raw_os_error();
                            // Error 10054 on Windows is WSAECONNRESET from ICMP port unreachable
                            if raw != Some(10054) && last_error_log.elapsed() >= Duration::from_secs(3) {
                                last_error_log = Instant::now();
                                eprintln!("[!] Server recv error: {}", e);
                            }
                            thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            }
        });

        // 3. STUN Keepalive Timer Loop: sends STUN Binding Request every 10 seconds
        if is_stun {
            let running_timer = running;
            thread::spawn(move || {
                while running_timer.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(10));
                    if !running_timer.load(Ordering::Relaxed) {
                        break;
                    }
                    let bind_req = stun_build_binding_request();
                    let _ = upstream_ping.send(&bind_req);
                }
            });
        }

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
