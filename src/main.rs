#![windows_subsystem = "windows"]

mod crc8;
mod obfuscator;
mod stun;
mod archive;
mod windows_net;
mod relay;
pub mod wg_config;
pub mod wintun_adapter;
pub mod tunnel;
pub mod profile_store;
pub mod tunnel_service;
pub mod gui;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use archive::PhobosProfile;
use relay::PhobosRelay;
use tunnel::StandaloneTunnel;
use windows_net::bind_socket_to_physical_interface;
use wintun_adapter::WintunDevice;

fn main() {
    let raw_args: Vec<String> = env::args().collect();
    let is_companion_mode = raw_args.iter().any(|a| a == "--companion" || a == "-c");
    let is_cli_mode = raw_args.iter().any(|a| a == "--cli");
    let is_help = raw_args.iter().any(|a| a == "--help" || a == "-h");

    // Attach to parent terminal only if user invoked CLI/help flags from a console
    #[cfg(windows)]
    if is_companion_mode || is_cli_mode || is_help {
        unsafe {
            windows_sys::Win32::System::Console::AttachConsole(windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS);
        }
    }

    if is_help {
        println!("============================================================");
        println!("        Phobos WireGuard Client for Windows (Rust)          ");
        println!("============================================================");
        println!("Использование:");
        println!("  phobos-client.exe                - Запуск графического интерфейса (GUI)");
        println!("  phobos-client.exe <файл.tar.gz>  - Импорт профиля и запуск GUI");
        println!("  phobos-client.exe --cli          - Консольный режим самостоятельного туннеля");
        println!("  phobos-client.exe --companion    - Режим компаньона (прокси для офиц. WireGuard)");
        println!("  phobos-client.exe --help         - Справка");
        return;
    }

    // 1. Check for administrator rights on Windows (required for Wintun virtual network adapter)
    #[cfg(windows)]
    if !is_companion_mode && !windows_net::is_admin() {
        if is_cli_mode {
            println!("============================================================");
            println!("        Phobos WireGuard Client for Windows (Rust)          ");
            println!("============================================================");
            println!("[*] Для создания виртуального сетевого адаптера Wintun требуются");
            println!("    права Администратора.");
            println!("[*] Запрос UAC повышения привилегий...");
        }

        if let Err(e) = windows_net::elevate_and_relaunch() {
            if is_cli_mode {
                eprintln!("[!] Ошибка: {}", e);
                eprintln!("[!] Запустите программу от имени Администратора (ПКМ -> Запуск от имени администратора).");
                wait_for_keypress();
            }
            return;
        }
        return; // Child process started, parent terminates
    }

    // 2. Check if a file was passed (e.g. dragged onto the executable)
    let passed_file = raw_args.iter().skip(1).find(|a| !a.starts_with('-')).map(|s| clean_path(s));

    if let Some(ref file_path) = passed_file {
        if file_path.is_file() && profile_store::is_supported_profile_path(file_path) {
            // Import into profile store
            let _ = profile_store::import_profile(file_path);
        }
    }

    // 3. Select mode: GUI (default) or CLI
    if is_companion_mode {
        println!("============================================================");
        println!("        Phobos WireGuard Companion for Windows (Rust)       ");
        println!("============================================================");
        let path = passed_file.unwrap_or_else(find_or_prompt_package);
        let profile = match PhobosProfile::load_from_file(&path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[!] Ошибка загрузки: {}", e);
                return;
            }
        };
        run_companion_mode(profile);
    } else if is_cli_mode {
        println!("============================================================");
        println!("        Phobos WireGuard Client for Windows (Rust)          ");
        println!("============================================================");
        let path = passed_file.unwrap_or_else(find_or_prompt_package);
        let profile = match PhobosProfile::load_from_file(&path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[!] Ошибка загрузки: {}", e);
                return;
            }
        };
        run_standalone_cli_mode(&profile);
    } else {
        // DEFAULT: Launch full GUI client
        if let Err(e) = gui::run_gui() {
            eprintln!("[!] Ошибка запуска графического интерфейса: {}", e);
            wait_for_keypress();
        }
    }
}

/// Runs standalone CLI mode
fn run_standalone_cli_mode(profile: &PhobosProfile) {
    println!();
    println!("[+] Загружен профиль:     {}", profile.client_name);
    println!("[+] Целевой сервер:       {}", profile.target);
    println!("[+] Режим маскировки:     {}", profile.masking);

    let wg_conf = match profile.parse_wg_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] Ошибка парсинга конфигурации WireGuard: {}", e);
            wait_for_keypress();
            return;
        }
    };

    println!("[+] Локальный IP адрес:   {}/{}", wg_conf.client_ipv4, wg_conf.client_ipv4_prefix);
    println!("[+] MTU туннеля:          {}", wg_conf.mtu);
    println!("[+] DNS серверы:          {:?}", wg_conf.dns_servers);
    println!("------------------------------------------------------------");

    let target_addr: SocketAddr = match profile.target.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                eprintln!("[!] Не удалось определить IP сервера: {}", profile.target);
                wait_for_keypress();
                return;
            }
        },
        Err(e) => {
            eprintln!("[!] Ошибка разрешения адреса {}: {}", profile.target, e);
            wait_for_keypress();
            return;
        }
    };

    let target_ipv4 = match target_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => {
            eprintln!("[!] IPv6 адреса серверов пока не поддерживаются.");
            wait_for_keypress();
            return;
        }
    };

    let dummy_sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] Ошибка сокета: {}", e);
            wait_for_keypress();
            return;
        }
    };

    let physical_if_index = match bind_socket_to_physical_interface(&dummy_sock, &target_addr) {
        Ok(idx) => idx,
        Err(e) => {
            eprintln!("[!] Ошибка определения сетевого интерфейса: {}", e);
            wait_for_keypress();
            return;
        }
    };

    println!("[*] Инициализация виртуального сетевого адаптера Wintun...");
    let wintun_dev = match WintunDevice::create(&wg_conf, target_ipv4, physical_if_index) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("[!] Ошибка создания адаптера Wintun: {}", e);
            wait_for_keypress();
            return;
        }
    };

    let tunnel = Arc::new(StandaloneTunnel::new());
    let tunnel_for_signal = tunnel.clone();

    let _ = ctrlc::set_handler(move || {
        println!("\n[!] Получен сигнал Ctrl+C. Отключение VPN и очистка маршрутов...");
        tunnel_for_signal.stop();
    });

    println!("------------------------------------------------------------");
    println!("VPN ПОДКЛЮЧЕН! Для отключения нажмите Ctrl+C в этом окне.");
    println!("------------------------------------------------------------");

    if let Err(e) = tunnel.run(profile, &wg_conf, wintun_dev) {
        eprintln!("[!] Ошибка работы туннеля: {}", e);
    }

    println!("[+] До свидания!");
}

/// Runs companion proxy mode (exports .conf for official WireGuard app)
fn run_companion_mode(mut profile: PhobosProfile) {
    let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let ready_conf_path = match profile.export_ready_wg_conf(&current_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] Ошибка создания файла конфигурации WireGuard: {}", e);
            return;
        }
    };

    println!();
    println!("[+] Успешно загружен профиль: {}", profile.client_name);
    println!("[+] Целевой сервер Phobos:   {}", profile.target);
    println!("[+] Локальный порт прокси:   127.0.0.1:{}", profile.local_port);
    println!("[+] Режим маскировки:        {}", profile.masking);
    println!();
    println!("------------------------------------------------------------");
    println!("ГОТОВО! Создан файл конфигурации для WireGuard:");
    println!("  -> {}", ready_conf_path.display());
    println!("------------------------------------------------------------");
    println!("ИНСТРУКЦИЯ ПО ПОДКЛЮЧЕНИЮ:");
    println!("  1. Откройте официальную программу 'WireGuard for Windows'");
    println!("  2. Нажмите 'Добавить туннель' (Ctrl+O) и выберите файл:");
    println!("     {}", ready_conf_path.file_name().unwrap_or_default().to_string_lossy());
    println!("  3. Нажмите кнопку 'Подключить' в WireGuard");
    println!("  4. Не закрывайте это окно, пока используете VPN!");
    println!("------------------------------------------------------------");
    println!();

    let relay = Arc::new(PhobosRelay::new(Arc::new(profile)));
    if let Err(e) = relay.start() {
        eprintln!("[!] Не удалось запустить локальный релей: {}", e);
        return;
    }

    let relay_for_stats = relay.clone();
    let stats = relay.stats.clone();

    // Spawn monitor thread
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));
            let up = stats.bytes_up.load(Ordering::Relaxed);
            let down = stats.bytes_down.load(Ordering::Relaxed);
            let pkts_up = stats.pkts_up.load(Ordering::Relaxed);
            let pkts_down = stats.pkts_down.load(Ordering::Relaxed);

            print!(
                "\r[Статус] Передано: {:.2} MB ({} пак.) | Принято: {:.2} MB ({} пак.)   ",
                up as f64 / 1_048_576.0,
                pkts_up,
                down as f64 / 1_048_576.0,
                pkts_down
            );
            let _ = io::stdout().flush();
        }
    });

    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r_sig = running.clone();
    let _ = ctrlc::set_handler(move || {
        println!("\n[!] Остановка релея Phobos...");
        r_sig.store(false, Ordering::SeqCst);
    });

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }

    relay_for_stats.stop();
    println!("[+] Релей успешно остановлен.");

    // Secure cleanup of plain-text WireGuard configuration containing PrivateKey
    if ready_conf_path.exists() {
        print!(
            "\n[?] Удалить временный файл конфигурации WireGuard '{}' для безопасности? [Y/n]: ",
            ready_conf_path.file_name().unwrap_or_default().to_string_lossy()
        );
        let _ = io::stdout().flush();
        let mut ans = String::new();
        if io::stdin().read_line(&mut ans).is_ok() {
            let trimmed = ans.trim().to_lowercase();
            if trimmed.is_empty() || trimmed == "y" || trimmed == "yes" || trimmed == "д" || trimmed == "да" {
                if let Err(e) = fs::remove_file(&ready_conf_path) {
                    eprintln!("[!] Не удалось удалить временный файл: {}", e);
                } else {
                    println!("[+] Временный файл конфигурации успешно удален.");
                }
            } else {
                println!("[*] Файл сохранён: {}", ready_conf_path.display());
            }
        }
    }

    println!("[+] До свидания!");
}

fn clean_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    let unquoted = trimmed.trim_matches('"').trim_matches('\'');
    PathBuf::from(unquoted)
}

fn find_or_prompt_package() -> PathBuf {
    if let Ok(entries) = fs::read_dir(".") {
        let mut tar_files = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && profile_store::is_supported_profile_path(&path) {
                tar_files.push(path);
            }
        }

        if tar_files.len() == 1 {
            println!("[*] Обнаружен файл пакета/профиля: {}", tar_files[0].display());
            return tar_files.remove(0);
        }
    }

    loop {
        println!("\nПеретащите файл пакета Phobos (.tar.gz, .tgz, .conf) в это окно и нажмите Enter:");
        print!("> ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let path = clean_path(&input);
            if path.is_file() {
                if profile_store::is_supported_profile_path(&path) {
                    return path;
                } else {
                    println!("[!] Неподдерживаемый формат файла. Поддерживаются .tar.gz, .tgz, .conf, .enc");
                    continue;
                }
            }
            println!("[!] Файл не найден или не является обычным файлом: {}", path.display());
        }
    }
}

fn wait_for_keypress() {
    println!("\nНажмите Enter для выхода...");
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
}
