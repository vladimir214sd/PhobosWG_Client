// Safe Wintun interface manager and routing controller for Windows

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

use crate::wg_config::WireGuardConfig;
use crate::windows_net::{
    add_ip_route, add_unicast_ip, delete_ip_route, get_best_route_gateway, set_interface_dns,
    set_interface_mtu,
};

const WINTUN_DLL_BYTES: &[u8] = include_bytes!("../wintun.dll");

/// Ensures wintun.dll is available on the filesystem, extracting the embedded binary if necessary.
pub fn ensure_wintun_dll() -> Result<PathBuf, String> {
    // 1. Check next to the current running executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let path = exe_dir.join("wintun.dll");
            if path.exists() {
                return Ok(path);
            }
            // Try extracting next to the executable
            if fs::write(&path, WINTUN_DLL_BYTES).is_ok() {
                return Ok(path);
            }
        }
    }

    // 2. Check current working directory
    let cwd_path = PathBuf::from("wintun.dll");
    if cwd_path.exists() {
        return Ok(cwd_path);
    }
    if fs::write(&cwd_path, WINTUN_DLL_BYTES).is_ok() {
        return Ok(cwd_path);
    }

    // 3. Fallback to system %TEMP% folder
    let temp_path = std::env::temp_dir().join("phobos_wintun.dll");
    if !temp_path.exists() || fs::metadata(&temp_path).map(|m| m.len()).unwrap_or(0) != WINTUN_DLL_BYTES.len() as u64 {
        fs::write(&temp_path, WINTUN_DLL_BYTES)
            .map_err(|e| format!("Failed to extract wintun.dll to temp directory: {}", e))?;
    }

    Ok(temp_path)
}

pub struct VpnRouteManager {
    server_ip: Ipv4Addr,
    gateway_ip: Option<Ipv4Addr>,
    physical_if_index: u32,
    adapter_if_index: u32,
    pub adapter_ip: Ipv4Addr,
    routes_installed: bool,
}

impl VpnRouteManager {
    pub fn new(
        server_ip: Ipv4Addr,
        physical_if_index: u32,
        adapter_if_index: u32,
        adapter_ip: Ipv4Addr,
    ) -> Self {
        let gateway_ip = get_best_route_gateway(server_ip).map(|(gw, _)| gw);

        Self {
            server_ip,
            gateway_ip,
            physical_if_index,
            adapter_if_index,
            adapter_ip,
            routes_installed: false,
        }
    }

    /// Installs routing table entries to direct all traffic into the VPN tunnel via pure Win32 API
    pub fn install_routes(&mut self) -> Result<(), String> {
        let gw_opt = self.gateway_ip.map(IpAddr::V4);
        let gw_str = match self.gateway_ip {
            Some(gw) if gw != Ipv4Addr::UNSPECIFIED => gw.to_string(),
            _ => self.server_ip.to_string(),
        };

        println!("[*] Настройка маршрутизации Windows (Win32 IP Helper)...");
        println!("    -> Маршрут к серверу Phobos: {}/32 через шлюз {} (интерфейс #{})",
            self.server_ip, gw_str, self.physical_if_index);

        // 1. Direct host route to Phobos server via physical gateway
        let res = add_ip_route(
            self.physical_if_index,
            IpAddr::V4(self.server_ip),
            32,
            gw_opt,
            1,
        );
        if let Err(e) = res {
            eprintln!("[!] Предупреждение: не удалось добавить прямой маршрут к серверу: {}", e);
        }

        // 2. Default VPN routes using standard two /1 halves: 0.0.0.0/1 and 128.0.0.0/1
        println!("    -> VPN маршруты 0.0.0.0/1 и 128.0.0.0/1 через Wintun (интерфейс #{})", self.adapter_if_index);

        add_ip_route(
            self.adapter_if_index,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            1,
            None,
            1,
        ).map_err(|e| format!("Failed to add 0.0.0.0/1 route: {}", e))?;

        add_ip_route(
            self.adapter_if_index,
            IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
            1,
            None,
            1,
        ).map_err(|e| format!("Failed to add 128.0.0.0/1 route: {}", e))?;

        self.routes_installed = true;
        println!("[+] Маршруты успешно установлены. Весь интернет-трафик направлен в туннель.");
        Ok(())
    }

    /// Removes all installed VPN routes via pure Win32 API
    pub fn remove_routes(&mut self) {
        if !self.routes_installed {
            return;
        }

        println!("[*] Восстановление исходных маршрутов Windows (Win32 IP Helper)...");
        let gw_opt = self.gateway_ip.map(IpAddr::V4);
        let _ = delete_ip_route(self.physical_if_index, IpAddr::V4(self.server_ip), 32, gw_opt);
        let _ = delete_ip_route(self.adapter_if_index, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1, None);
        let _ = delete_ip_route(self.adapter_if_index, IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1, None);

        self.routes_installed = false;
        println!("[+] Маршруты очищены.");
    }
}

impl Drop for VpnRouteManager {
    fn drop(&mut self) {
        self.remove_routes();
    }
}

pub struct WintunDevice {
    pub adapter: Arc<wintun::Adapter>,
    pub session: Arc<wintun::Session>,
    pub route_manager: VpnRouteManager,
}

impl WintunDevice {
    /// Creates and configures the Wintun adapter and network routes
    pub fn create(
        wg_conf: &WireGuardConfig,
        server_ip: Ipv4Addr,
        physical_if_index: u32,
    ) -> Result<Self, String> {
        let dll_path = ensure_wintun_dll()?;
        let wintun = unsafe { wintun::load_from_path(&dll_path) }
            .map_err(|e| format!("Failed to load wintun driver from {}: {:?}", dll_path.display(), e))?;

        let adapter_name = "Phobos";

        // If adapter exists from previous run, try opening it first or create new
        let adapter = match wintun::Adapter::open(&wintun, adapter_name) {
            Ok(a) => {
                println!("[*] Обнаружен существующий адаптер Wintun: {}", adapter_name);
                a
            }
            Err(_) => {
                println!("[*] Создание виртуального сетевого адаптера Wintun: {}", adapter_name);
                wintun::Adapter::create(&wintun, adapter_name, "PhobosWG", None)
                    .map_err(|e| format!("Failed to create Wintun adapter: {:?}", e))?
            }
        };

        let adapter_if_index = adapter.get_adapter_index()
            .map_err(|e| format!("Failed to get adapter interface index: {:?}", e))?;

        // 1. Configure MTU via pure Win32 API (zero external processes)
        let _ = set_interface_mtu(adapter_if_index, wg_conf.mtu as u32);

        // 2. Configure IPv4 address via pure Win32 API (zero external processes)
        add_unicast_ip(
            adapter_if_index,
            IpAddr::V4(wg_conf.client_ipv4),
            wg_conf.client_ipv4_prefix,
        ).map_err(|e| format!("Failed to set adapter IPv4: {}", e))?;

        // 3. Configure IPv6 address if present via pure Win32 API (zero external processes)
        if let Some(v6) = wg_conf.client_ipv6 {
            let _ = add_unicast_ip(adapter_if_index, IpAddr::V6(v6), 128);
        }

        // 4. Configure DNS servers via pure Win32 API (zero external processes)
        if !wg_conf.dns_servers.is_empty() {
            let _ = set_interface_dns(adapter.get_guid(), &wg_conf.dns_servers);
        }

        println!("[+] Адаптер настроен: IP {}/{}, MTU {}, Interface #{}",
            wg_conf.client_ipv4, wg_conf.client_ipv4_prefix, wg_conf.mtu, adapter_if_index);

        let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| format!("Failed to start Wintun session: {:?}", e))?);

        let mut route_manager = VpnRouteManager::new(
            server_ip,
            physical_if_index,
            adapter_if_index,
            wg_conf.client_ipv4,
        );

        route_manager.install_routes()?;

        Ok(Self {
            adapter,
            session,
            route_manager,
        })
    }

    /// Graceful teardown
    pub fn shutdown(&mut self) {
        let _ = self.session.shutdown();
        self.route_manager.remove_routes();
    }
}

impl Drop for WintunDevice {
    fn drop(&mut self) {
        self.shutdown();
    }
}
