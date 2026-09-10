// Standalone WireGuard tunnel engine with Phobos obfuscation and STUN masking

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::archive::PhobosProfile;
use crate::obfuscator::Obfuscator;
use crate::stun::{is_stun_packet, stun_build_binding_request, stun_unwrap_data_indication, stun_wrap_data_indication};
use crate::wg_config::WireGuardConfig;
use crate::windows_net::{bind_socket_to_physical_interface, disable_udp_connreset};
use crate::wintun_adapter::WintunDevice;

pub struct StandaloneTunnel {
    running: Arc<AtomicBool>,
    bytes_sent: Arc<AtomicU64>,
    bytes_recv: Arc<AtomicU64>,
}

impl StandaloneTunnel {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_recv: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn run(
        &self,
        profile: &PhobosProfile,
        wg_conf: &WireGuardConfig,
        mut wintun_dev: WintunDevice,
    ) -> Result<(), String> {
        // 1. Resolve remote server address
        let target_addr: SocketAddr = profile.target.to_socket_addrs()
            .map_err(|e| format!("Failed to resolve target '{}': {}", profile.target, e))?
            .next()
            .ok_or_else(|| format!("No address found for target '{}'", profile.target))?;

        // 2. Setup UDP socket to server
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        disable_udp_connreset(&socket);

        // Bind socket to physical interface via IP_UNICAST_IF to prevent routing loops
        let if_idx = bind_socket_to_physical_interface(&socket, &target_addr)
            .map_err(|e| format!("Failed to bind socket to physical interface: {}", e))?;
        println!("[+] UDP сокет привязан к физическому интерфейсу #{}", if_idx);

        socket.connect(target_addr)
            .map_err(|e| format!("Failed to connect UDP socket to {}: {}", target_addr, e))?;

        let socket = Arc::new(socket);

        // 3. Initialize BoringTun WireGuard engine
        let static_private = StaticSecret::from(wg_conf.private_key);
        let peer_static_public = PublicKey::from(wg_conf.peer_public_key);
        let preshared_key = wg_conf.preshared_key;
        let persistent_keepalive = wg_conf.persistent_keepalive.or(Some(25));
        let index = rand::random::<u32>();

        let tunn = Tunn::new(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            None,
        );
        let tunn = Arc::new(Mutex::new(tunn));

        // 4. Initialize Phobos Obfuscator
        let obfuscator = Arc::new(Mutex::new(Obfuscator::new(
            profile.key.clone(),
            profile.max_dummy,
            profile.obfuscate_bytes,
        )));

        let use_stun = profile.masking.eq_ignore_ascii_case("STUN");

        // 5. Send initial WireGuard handshake initiation packet
        {
            let mut hs_buf = [0u8; 2048];
            let mut tunn_lock = tunn.lock().unwrap();
            if let TunnResult::WriteToNetwork(hs_packet) = tunn_lock.format_handshake_initiation(&mut hs_buf, false) {
                let mut obf_buf = hs_packet.to_vec();
                let obf_lock = obfuscator.lock().unwrap();
                obf_lock.encode(&mut obf_buf);
                drop(obf_lock);

                let payload = if use_stun {
                    stun_wrap_data_indication(&obf_buf)
                } else {
                    obf_buf
                };

                let _ = socket.send(&payload);
                self.bytes_sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
                println!("[*] Отправлен пакет инициализации WireGuard Handshake к {}", target_addr);
            }
        }

        // Send initial STUN keepalive if STUN masking is used
        if use_stun {
            let req = stun_build_binding_request();
            let _ = socket.send(&req);
        }

        println!("[+] Туннель активен. Ожидание первого ответа сервера...");

        // 6. Spawn worker threads
        let running = self.running.clone();
        let bytes_sent = self.bytes_sent.clone();
        let bytes_recv = self.bytes_recv.clone();

        // Worker Thread 1: TUN -> Obfuscator -> UDP
        let session_tun_read = wintun_dev.session.clone();
        let socket_tun_read = socket.clone();
        let tunn_tun_read = tunn.clone();
        let obf_tun_read = obfuscator.clone();
        let running_tun_read = running.clone();

        let t1 = thread::Builder::new().name("tun-to-udp".to_string()).spawn(move || {
            let mut wg_enc_buf = [0u8; 65535];

            while running_tun_read.load(Ordering::Relaxed) {
                let packet = match session_tun_read.receive_blocking() {
                    Ok(p) => p,
                    Err(_) => break, // Session shutdown
                };

                let mut tunn_lock = match tunn_tun_read.lock() {
                    Ok(l) => l,
                    Err(_) => break,
                };

                let res = tunn_lock.encapsulate(packet.bytes(), &mut wg_enc_buf);
                drop(tunn_lock);

                match res {
                    TunnResult::WriteToNetwork(wg_pkt) => {
                        let mut obf_buf = wg_pkt.to_vec();
                        let obf_lock = obf_tun_read.lock().unwrap();
                        obf_lock.encode(&mut obf_buf);
                        drop(obf_lock);

                        let payload = if use_stun {
                            stun_wrap_data_indication(&obf_buf)
                        } else {
                            obf_buf
                        };

                        if let Ok(n) = socket_tun_read.send(&payload) {
                            bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                    _ => {}
                }
            }
        }).map_err(|e| format!("Failed to spawn TUN reader thread: {}", e))?;

        // Worker Thread 2: UDP -> Deobfuscator -> TUN
        let session_udp_read = wintun_dev.session.clone();
        let socket_udp_read = socket.clone();
        let tunn_udp_read = tunn.clone();
        let obf_udp_read = obfuscator.clone();
        let running_udp_read = running.clone();

        let t2 = thread::Builder::new().name("udp-to-tun".to_string()).spawn(move || {
            let mut udp_buf = [0u8; 65535];
            let mut wg_dec_buf = [0u8; 65535];

            while running_udp_read.load(Ordering::Relaxed) {
                let n = match socket_udp_read.recv(&mut udp_buf) {
                    Ok(n) => n,
                    Err(_) => {
                        if !running_udp_read.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                };

                bytes_recv.fetch_add(n as u64, Ordering::Relaxed);
                let raw_data = &udp_buf[..n];

                let de_stun = if use_stun {
                    match stun_unwrap_data_indication(raw_data) {
                        Some(p) => p,
                        None => {
                            // If it's a STUN response packet, ignore silently
                            if is_stun_packet(raw_data) {
                                continue;
                            }
                            raw_data
                        }
                    }
                } else {
                    raw_data
                };

                let mut plain_buf = de_stun.to_vec();
                let obf_lock = obf_udp_read.lock().unwrap();
                let ok = obf_lock.decode(&mut plain_buf);
                drop(obf_lock);

                if !ok || plain_buf.is_empty() {
                    continue;
                }

                let mut tunn_lock = match tunn_udp_read.lock() {
                    Ok(l) => l,
                    Err(_) => break,
                };

                let mut res = tunn_lock.decapsulate(None, &plain_buf, &mut wg_dec_buf);
                loop {
                    match res {
                        TunnResult::WriteToTunnelV4(ip_pkt, _) | TunnResult::WriteToTunnelV6(ip_pkt, _) => {
                            if let Ok(mut send_pkt) = session_udp_read.allocate_send_packet(ip_pkt.len() as u16) {
                                send_pkt.bytes_mut().copy_from_slice(ip_pkt);
                                session_udp_read.send_packet(send_pkt);
                            }
                        }
                        TunnResult::WriteToNetwork(wg_pkt) => {
                            let mut obf_buf = wg_pkt.to_vec();
                            let obf_lock = obf_udp_read.lock().unwrap();
                            obf_lock.encode(&mut obf_buf);
                            drop(obf_lock);

                            let payload = if use_stun {
                                stun_wrap_data_indication(&obf_buf)
                            } else {
                                obf_buf
                            };

                            let _ = socket_udp_read.send(&payload);
                        }
                        _ => break,
                    }

                    res = tunn_lock.decapsulate(None, &[], &mut wg_dec_buf);
                }
            }
        }).map_err(|e| format!("Failed to spawn UDP reader thread: {}", e))?;

        // Worker Thread 3: Periodic Timers & STUN Keepalive
        let socket_timer = socket.clone();
        let tunn_timer = tunn.clone();
        let obf_timer = obfuscator.clone();
        let running_timer = running.clone();

        let t3 = thread::Builder::new().name("keepalive-timer".to_string()).spawn(move || {
            let mut timer_buf = [0u8; 2048];
            let mut last_stun = Instant::now();

            while running_timer.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(250));

                // 1. BoringTun internal timer update (re-keying, handshake timers)
                {
                    if let Ok(mut tunn_lock) = tunn_timer.lock() {
                        if let TunnResult::WriteToNetwork(wg_pkt) = tunn_lock.update_timers(&mut timer_buf) {
                            let mut obf_buf = wg_pkt.to_vec();
                            let obf_lock = obf_timer.lock().unwrap();
                            obf_lock.encode(&mut obf_buf);
                            drop(obf_lock);

                            let payload = if use_stun {
                                stun_wrap_data_indication(&obf_buf)
                            } else {
                                obf_buf
                            };

                            let _ = socket_timer.send(&payload);
                        }
                    }
                }

                // 2. Phobos STUN keepalive every 10 seconds
                if use_stun && last_stun.elapsed() >= Duration::from_secs(10) {
                    last_stun = Instant::now();
                    let req = stun_build_binding_request();
                    let _ = socket_timer.send(&req);
                }
            }
        }).map_err(|e| format!("Failed to spawn timer thread: {}", e))?;

        // Live status dashboard in current thread
        let mut last_sent = 0u64;
        let mut last_recv = 0u64;
        let mut last_check = Instant::now();
        let mut handshake_notified = false;

        while self.running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(1000));
            let elapsed = last_check.elapsed().as_secs_f64();
            last_check = Instant::now();

            let cur_sent = self.bytes_sent.load(Ordering::Relaxed);
            let cur_recv = self.bytes_recv.load(Ordering::Relaxed);

            let sent_rate = ((cur_sent - last_sent) as f64 / elapsed) / 1024.0;
            let recv_rate = ((cur_recv - last_recv) as f64 / elapsed) / 1024.0;

            last_sent = cur_sent;
            last_recv = cur_recv;

            let hs_info = if let Ok(tunn_lock) = tunn.lock() {
                let (since_hs, _, _, _, _) = tunn_lock.stats();
                match since_hs {
                    Some(dur) => {
                        if !handshake_notified {
                            println!("\n[+] WireGuard Handshake УСПЕШНО ЗАВЕРШЁН! Соединение защищено.");
                            handshake_notified = true;
                        }
                        format!("Подключено (Handshake {} сек. назад)", dur.as_secs())
                    }
                    None => "Инициализация рукопожатия...".to_string(),
                }
            } else {
                "---".to_string()
            };

            print!(
                "\r[VPN] {} | ↑ {:>6.1} KB/s | ↓ {:>6.1} KB/s | Всего: Sent {:>5.1} MB, Recv {:>5.1} MB  ",
                hs_info,
                sent_rate,
                recv_rate,
                cur_sent as f64 / (1024.0 * 1024.0),
                cur_recv as f64 / (1024.0 * 1024.0),
            );
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }

        println!("\n[*] Завершение работы туннеля...");
        wintun_dev.shutdown();

        let _ = t1.join();
        let _ = t2.join();
        let _ = t3.join();

        println!("[+] Туннель отключен.");
        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
