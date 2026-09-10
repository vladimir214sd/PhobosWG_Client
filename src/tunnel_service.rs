// Background tunnel controller and state manager for GUI

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
use crate::windows_net::{bind_socket_to_physical_interface, disable_udp_connreset};
use crate::wintun_adapter::WintunDevice;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub rate_sent_kbps: f64,
    pub rate_recv_kbps: f64,
    pub last_handshake_secs: Option<u64>,
}

pub struct TunnelService {
    pub status: Arc<Mutex<TunnelStatus>>,
    pub stats: Arc<Mutex<TunnelStats>>,
    pub logs: Arc<Mutex<Vec<String>>>,
    pub active_profile_name: Arc<Mutex<Option<String>>>,
    stop_signal: Arc<AtomicBool>,
}

impl TunnelService {
    pub fn new() -> Self {
        Self {
            status: Arc::new(Mutex::new(TunnelStatus::Disconnected)),
            stats: Arc::new(Mutex::new(TunnelStats::default())),
            logs: Arc::new(Mutex::new(Vec::new())),
            active_profile_name: Arc::new(Mutex::new(None)),
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn log(&self, msg: impl Into<String>) {
        let text = format!("[{}] {}", current_time_str(), msg.into());
        if let Ok(mut logs) = self.logs.lock() {
            if logs.len() >= 2000 {
                let drain_count = logs.len() - 1500;
                logs.drain(0..drain_count);
            }
            logs.push(text);
        }
    }

    pub fn start(&self, profile: PhobosProfile) {
        // Disconnect existing if any and wait for previous session to terminate
        if self.is_active() {
            self.stop();
            for _ in 0..40 {
                if !self.is_active() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }

        self.stop_signal.store(false, Ordering::Relaxed);
        *self.active_profile_name.lock().unwrap() = Some(profile.client_name.clone());
        *self.status.lock().unwrap() = TunnelStatus::Connecting;
        *self.stats.lock().unwrap() = TunnelStats::default();

        let client_name = profile.client_name.clone();
        self.log(format!("Запуск профиля: '{}' (цель: {})", client_name, profile.target));

        let status_arc = self.status.clone();
        let stats_arc = self.stats.clone();
        let logs_arc = self.logs.clone();
        let active_name_arc = self.active_profile_name.clone();
        let stop_signal = self.stop_signal.clone();

        thread::spawn(move || {
            let log_fn = |msg: String| {
                let text = format!("[{}] {}", current_time_str(), msg);
                if let Ok(mut logs) = logs_arc.lock() {
                    logs.push(text);
                }
            };

            // 1. Parse WireGuard config
            let wg_conf = match profile.parse_wg_config() {
                Ok(c) => c,
                Err(e) => {
                    log_fn(format!("Ошибка парсинга конфигурации: {}", e));
                    *status_arc.lock().unwrap() = TunnelStatus::Error(e);
                    *active_name_arc.lock().unwrap() = None;
                    return;
                }
            };

            log_fn(format!("WireGuard параметры: IP {}/{}, MTU {}",
                wg_conf.client_ipv4, wg_conf.client_ipv4_prefix, wg_conf.mtu));

            // 2. Resolve server address
            let target_addr: SocketAddr = match profile.target.to_socket_addrs() {
                Ok(mut addrs) => match addrs.next() {
                    Some(a) => a,
                    None => {
                        let err = format!("Не удалось определить адрес: {}", profile.target);
                        log_fn(err.clone());
                        *status_arc.lock().unwrap() = TunnelStatus::Error(err);
                        *active_name_arc.lock().unwrap() = None;
                        return;
                    }
                },
                Err(e) => {
                    let err = format!("Ошибка разрешения адреса {}: {}", profile.target, e);
                    log_fn(err.clone());
                    *status_arc.lock().unwrap() = TunnelStatus::Error(err);
                    *active_name_arc.lock().unwrap() = None;
                    return;
                }
            };

            let target_ipv4 = match target_addr.ip() {
                std::net::IpAddr::V4(v4) => v4,
                std::net::IpAddr::V6(_) => {
                    let err = "IPv6 серверы пока не поддерживаются".to_string();
                    log_fn(err.clone());
                    *status_arc.lock().unwrap() = TunnelStatus::Error(err);
                    *active_name_arc.lock().unwrap() = None;
                    return;
                }
            };

            // 3. Find physical interface
            let dummy_sock = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    let err = format!("Ошибка сокета: {}", e);
                    log_fn(err.clone());
                    *status_arc.lock().unwrap() = TunnelStatus::Error(err);
                    *active_name_arc.lock().unwrap() = None;
                    return;
                }
            };

            let physical_if_index = match bind_socket_to_physical_interface(&dummy_sock, &target_addr) {
                Ok(idx) => idx,
                Err(e) => {
                    let err = format!("Ошибка физического интерфейса: {}", e);
                    log_fn(err.clone());
                    *status_arc.lock().unwrap() = TunnelStatus::Error(err);
                    *active_name_arc.lock().unwrap() = None;
                    return;
                }
            };
            drop(dummy_sock);

            // 4. Create Wintun adapter & install routes
            log_fn("Инициализация виртуального адаптера Wintun...".to_string());
            let mut wintun_dev = match WintunDevice::create(&wg_conf, target_ipv4, physical_if_index) {
                Ok(dev) => dev,
                Err(e) => {
                    let err = format!("Ошибка создания Wintun: {}", e);
                    log_fn(err.clone());
                    *status_arc.lock().unwrap() = TunnelStatus::Error(err);
                    *active_name_arc.lock().unwrap() = None;
                    return;
                }
            };

            log_fn(format!("Адаптер готов. Маршруты 0.0.0.0/1 и 128.0.0.0/1 направлены в VPN"));

            // 5. Setup UDP socket
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    let err = format!("Ошибка UDP сокета: {}", e);
                    log_fn(err.clone());
                    *status_arc.lock().unwrap() = TunnelStatus::Error(err);
                    *active_name_arc.lock().unwrap() = None;
                    return;
                }
            };
            disable_udp_connreset(&socket);
            let _ = bind_socket_to_physical_interface(&socket, &target_addr);
            if let Err(e) = socket.connect(target_addr) {
                let err = format!("Ошибка подключения к {}: {}", target_addr, e);
                log_fn(err.clone());
                *status_arc.lock().unwrap() = TunnelStatus::Error(err);
                *active_name_arc.lock().unwrap() = None;
                return;
            }
            let _ = socket.set_read_timeout(Some(Duration::from_millis(250)));
            let socket = Arc::new(socket);

            // 6. BoringTun & Obfuscator
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

            let obfuscator = Arc::new(Mutex::new(Obfuscator::new(
                profile.key.clone(),
                profile.max_dummy,
                profile.obfuscate_bytes,
            )));

            let use_stun = profile.masking.eq_ignore_ascii_case("STUN");

            let bytes_sent = Arc::new(AtomicU64::new(0));
            let bytes_recv = Arc::new(AtomicU64::new(0));

            // Send initial handshake
            {
                let mut hs_buf = [0u8; 2048];
                let mut tunn_lock = tunn.lock().unwrap();
                if let TunnResult::WriteToNetwork(hs_packet) = tunn_lock.format_handshake_initiation(&mut hs_buf, false) {
                    let mut obf_buf = hs_packet.to_vec();
                    obfuscator.lock().unwrap().encode(&mut obf_buf);
                    let payload = if use_stun {
                        stun_wrap_data_indication(&obf_buf).unwrap_or(obf_buf)
                    } else {
                        obf_buf
                    };
                    let _ = socket.send(&payload);
                    bytes_sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    log_fn(format!("Отправлен начальный запрос WireGuard Handshake к {}", target_addr));
                }
            }

            if use_stun {
                let req = stun_build_binding_request();
                let _ = socket.send(&req);
            }

            *status_arc.lock().unwrap() = TunnelStatus::Connecting;
            log_fn("Инициализация туннеля. Ожидание завершения WireGuard Handshake...".to_string());

            // Worker 1: TUN -> UDP
            let s_tun = wintun_dev.session.clone();
            let sock_1 = socket.clone();
            let tunn_1 = tunn.clone();
            let obf_1 = obfuscator.clone();
            let stop_1 = stop_signal.clone();
            let b_sent_1 = bytes_sent.clone();

            let t1 = thread::spawn(move || {
                let mut wg_enc_buf = [0u8; 65535];
                while !stop_1.load(Ordering::Relaxed) {
                    let packet = match s_tun.receive_blocking() {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    let mut tunn_lock = match tunn_1.lock() {
                        Ok(l) => l,
                        Err(_) => break,
                    };

                    let res = tunn_lock.encapsulate(packet.bytes(), &mut wg_enc_buf);
                    drop(tunn_lock);

                    if let TunnResult::WriteToNetwork(wg_pkt) = res {
                        let mut obf_buf = wg_pkt.to_vec();
                        obf_1.lock().unwrap().encode(&mut obf_buf);
                        let payload = if use_stun {
                            stun_wrap_data_indication(&obf_buf).unwrap_or(obf_buf)
                        } else {
                            obf_buf
                        };
                        if let Ok(n) = sock_1.send(&payload) {
                            b_sent_1.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                }
            });

            // Worker 2: UDP -> TUN
            let s_udp = wintun_dev.session.clone();
            let sock_2 = socket.clone();
            let tunn_2 = tunn.clone();
            let obf_2 = obfuscator.clone();
            let stop_2 = stop_signal.clone();
            let b_recv_2 = bytes_recv.clone();

            let t2 = thread::spawn(move || {
                let mut udp_buf = [0u8; 65535];
                let mut wg_dec_buf = [0u8; 65535];

                while !stop_2.load(Ordering::Relaxed) {
                    let n = match sock_2.recv(&mut udp_buf) {
                        Ok(n) => n,
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
                                continue;
                            }
                            if stop_2.load(Ordering::Relaxed) {
                                break;
                            }
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                    };

                    b_recv_2.fetch_add(n as u64, Ordering::Relaxed);
                    let raw = &udp_buf[..n];

                    let de_stun = if use_stun {
                        match stun_unwrap_data_indication(raw) {
                            Some(p) => p,
                            None => {
                                if is_stun_packet(raw) {
                                    continue;
                                }
                                raw
                            }
                        }
                    } else {
                        raw
                    };

                    let mut plain_buf = de_stun.to_vec();
                    let ok = obf_2.lock().unwrap().decode(&mut plain_buf);
                    if !ok || plain_buf.is_empty() {
                        continue;
                    }

                    let mut tunn_lock = match tunn_2.lock() {
                        Ok(l) => l,
                        Err(_) => break,
                    };

                    let mut res = tunn_lock.decapsulate(None, &plain_buf, &mut wg_dec_buf);
                    loop {
                        match res {
                            TunnResult::WriteToTunnelV4(ip_pkt, _) | TunnResult::WriteToTunnelV6(ip_pkt, _) => {
                                if let Ok(mut send_pkt) = s_udp.allocate_send_packet(ip_pkt.len() as u16) {
                                    send_pkt.bytes_mut().copy_from_slice(ip_pkt);
                                    s_udp.send_packet(send_pkt);
                                }
                            }
                            TunnResult::WriteToNetwork(wg_pkt) => {
                                let mut obf_buf = wg_pkt.to_vec();
                                obf_2.lock().unwrap().encode(&mut obf_buf);
                                let payload = if use_stun {
                                    stun_wrap_data_indication(&obf_buf).unwrap_or(obf_buf)
                                } else {
                                    obf_buf
                                };
                                let _ = sock_2.send(&payload);
                            }
                            _ => break,
                        }
                        res = tunn_lock.decapsulate(None, &[], &mut wg_dec_buf);
                    }
                }
            });

            // Worker 3: Timers
            let sock_3 = socket.clone();
            let tunn_3 = tunn.clone();
            let obf_3 = obfuscator.clone();
            let stop_3 = stop_signal.clone();

            let t3 = thread::spawn(move || {
                let mut timer_buf = [0u8; 2048];
                let mut last_stun = Instant::now();

                while !stop_3.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(250));

                    if let Ok(mut tunn_lock) = tunn_3.lock() {
                        if let TunnResult::WriteToNetwork(wg_pkt) = tunn_lock.update_timers(&mut timer_buf) {
                            let mut obf_buf = wg_pkt.to_vec();
                            obf_3.lock().unwrap().encode(&mut obf_buf);
                            let payload = if use_stun {
                                stun_wrap_data_indication(&obf_buf).unwrap_or(obf_buf)
                            } else {
                                obf_buf
                            };
                            let _ = sock_3.send(&payload);
                        }
                    }

                    if use_stun && last_stun.elapsed() >= Duration::from_secs(10) {
                        last_stun = Instant::now();
                        let req = stun_build_binding_request();
                        let _ = sock_3.send(&req);
                    }
                }
            });

            // Status monitor loop
            let mut last_sent = 0u64;
            let mut last_recv = 0u64;
            let mut last_time = Instant::now();
            let mut handshake_logged = false;

            while !stop_signal.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(500));
                let elapsed = last_time.elapsed().as_secs_f64();
                if elapsed < 0.1 { continue; }
                last_time = Instant::now();

                let cur_sent = bytes_sent.load(Ordering::Relaxed);
                let cur_recv = bytes_recv.load(Ordering::Relaxed);

                let rate_sent = ((cur_sent.saturating_sub(last_sent)) as f64 / elapsed) / 1024.0;
                let rate_recv = ((cur_recv.saturating_sub(last_recv)) as f64 / elapsed) / 1024.0;
                last_sent = cur_sent;
                last_recv = cur_recv;

                let last_hs_secs = if let Ok(tunn_lock) = tunn.lock() {
                    let (since_hs, _, _, _, _) = tunn_lock.stats();
                    if since_hs.is_some() && !handshake_logged {
                        log_fn("WireGuard Handshake УСПЕШНО завершён! Соединение установлено, трафик зашифрован.".to_string());
                        handshake_logged = true;
                        if let Ok(mut status_lock) = status_arc.lock() {
                            *status_lock = TunnelStatus::Connected;
                        }
                    }
                    since_hs.map(|d| d.as_secs())
                } else {
                    None
                };

                if let Ok(mut stats_lock) = stats_arc.lock() {
                    *stats_lock = TunnelStats {
                        bytes_sent: cur_sent,
                        bytes_recv: cur_recv,
                        rate_sent_kbps: rate_sent,
                        rate_recv_kbps: rate_recv,
                        last_handshake_secs: last_hs_secs,
                    };
                }
            }

            log_fn("Остановка туннеля и очистка маршрутов...".to_string());
            wintun_dev.shutdown();

            let _ = t1.join();
            let _ = t2.join();
            let _ = t3.join();

            log_fn("Туннель полностью отключен.".to_string());
            *status_arc.lock().unwrap() = TunnelStatus::Disconnected;
            *active_name_arc.lock().unwrap() = None;
        });
    }

    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::SeqCst);
    }

    pub fn is_active(&self) -> bool {
        matches!(*self.status.lock().unwrap(), TunnelStatus::Connected | TunnelStatus::Connecting)
    }
}

fn current_time_str() -> String {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct SystemTime {
            w_year: u16, w_month: u16, w_day_of_week: u16, w_day: u16,
            w_hour: u16, w_minute: u16, w_second: u16, w_milliseconds: u16,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetLocalTime(lpSystemTime: *mut SystemTime);
        }
        let mut st = SystemTime {
            w_year: 0, w_month: 0, w_day_of_week: 0, w_day: 0,
            w_hour: 0, w_minute: 0, w_second: 0, w_milliseconds: 0,
        };
        unsafe { GetLocalTime(&mut st) };
        format!("{:02}:{:02}:{:02}", st.w_hour, st.w_minute, st.w_second)
    }
    #[cfg(not(windows))]
    {
        "00:00:00".to_string()
    }
}
