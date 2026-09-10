// Windows network interface binding, routing helpers, and UAC elevation

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::windows::io::AsRawSocket;

#[repr(C)]
#[derive(Debug, Default)]
struct MibIpForwardRow {
    dw_forward_dest: u32,
    dw_forward_mask: u32,
    dw_forward_policy: u32,
    dw_forward_next_hop: u32,
    dw_forward_if_index: u32,
    dw_forward_type: u32,
    dw_forward_proto: u32,
    dw_forward_age: u32,
    dw_forward_next_hop_as: u32,
    dw_forward_metric1: u32,
    dw_forward_metric2: u32,
    dw_forward_metric3: u32,
    dw_forward_metric4: u32,
    dw_forward_metric5: u32,
}

#[cfg(windows)]
pub fn bind_socket_to_physical_interface(socket: &UdpSocket, target: &SocketAddr) -> Result<u32, String> {
    const IPPROTO_IP: i32 = 0;
    const IP_UNICAST_IF: i32 = 31;

    let handle = socket.as_raw_socket();

    match target.ip() {
        IpAddr::V4(ipv4) => {
            let dest_addr = u32::from_ne_bytes(ipv4.octets());
            let mut if_index: u32 = 0;

            // Call GetBestInterface from iphlpapi.dll
            #[link(name = "iphlpapi")]
            extern "system" {
                fn GetBestInterface(dwDestAddr: u32, pdwBestIfIndex: *mut u32) -> u32;
            }

            let ret = unsafe { GetBestInterface(dest_addr, &mut if_index) };
            if ret != 0 || if_index == 0 {
                return Err(format!("GetBestInterface failed with code {}", ret));
            }

            // On Windows IPv4, IP_UNICAST_IF requires network-byte-order index
            let net_index = if_index.to_be();
            let opt_ptr = &net_index as *const u32 as *const i8;
            let opt_len = std::mem::size_of::<u32>() as i32;

            #[link(name = "ws2_32")]
            extern "system" {
                fn setsockopt(s: usize, level: i32, optname: i32, optval: *const i8, optlen: i32) -> i32;
            }

            let res = unsafe { setsockopt(handle as usize, IPPROTO_IP, IP_UNICAST_IF, opt_ptr, opt_len) };
            if res != 0 {
                return Err(format!("setsockopt(IP_UNICAST_IF) failed with error {}", std::io::Error::last_os_error()));
            }

            Ok(if_index)
        }
        IpAddr::V6(_ipv6) => {
            Ok(0)
        }
    }
}

/// Finds the best route's next hop gateway and physical interface index for a destination IPv4
#[cfg(windows)]
pub fn get_best_route_gateway(target_ip: Ipv4Addr) -> Option<(Ipv4Addr, u32)> {
    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetBestRoute(dwDestAddr: u32, dwSourceAddr: u32, pBestRoute: *mut MibIpForwardRow) -> u32;
    }

    let dest = u32::from_ne_bytes(target_ip.octets());
    let mut row = MibIpForwardRow::default();
    let res = unsafe { GetBestRoute(dest, 0, &mut row) };
    if res == 0 {
        let gateway = Ipv4Addr::from(row.dw_forward_next_hop.to_ne_bytes());
        Some((gateway, row.dw_forward_if_index))
    } else {
        None
    }
}

/// Checks if current process is running with elevated administrator privileges (UAC elevated token)
#[cfg(windows)]
pub fn is_admin() -> bool {
    #[repr(C)]
    struct TokenElevationStruct {
        token_is_elevated: u32,
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION_CLASS: i32 = 20;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn CloseHandle(hObject: isize) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process_handle: isize, desired_access: u32, token_handle: *mut isize) -> i32;
        fn GetTokenInformation(
            token_handle: isize,
            token_information_class: i32,
            token_information: *mut std::ffi::c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    unsafe {
        let mut token_handle: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            return false;
        }

        let mut elevation = TokenElevationStruct { token_is_elevated: 0 };
        let mut ret_len = 0u32;
        let success = GetTokenInformation(
            token_handle,
            TOKEN_ELEVATION_CLASS,
            &mut elevation as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<TokenElevationStruct>() as u32,
            &mut ret_len,
        );

        CloseHandle(token_handle);
        success != 0 && elevation.token_is_elevated != 0
    }
}

/// Restricts file access control list (ACL) so only the Owner (current user) and Built-in Administrators
/// have access, blocking ACE inheritance from parent directories (SDDL: D:P(A;;GA;;;OW)(A;;GA;;;BA))
#[cfg(windows)]
pub fn set_file_owner_only_acl<P: AsRef<std::path::Path>>(path: P) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;

    const SDDL_REVISION_1: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x80000000;

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut std::ffi::c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;

        fn SetFileSecurityW(
            lp_file_name: *const u16,
            security_information: u32,
            p_security_descriptor: *const std::ffi::c_void,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    let sddl: Vec<u16> = OsStr::new("D:P(A;;GA;;;OW)(A;;GA;;;BA)")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let path_wide: Vec<u16> = OsStr::new(path.as_ref().as_os_str())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut p_sd: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut sd_size = 0u32;

        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut p_sd,
            &mut sd_size,
        ) == 0 {
            return Err("Failed to convert SDDL string to security descriptor".to_string());
        }

        let res = SetFileSecurityW(
            path_wide.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            p_sd,
        );

        LocalFree(p_sd);

        if res == 0 {
            return Err(format!("SetFileSecurityW failed with OS error {}", std::io::Error::last_os_error()));
        }
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn set_file_owner_only_acl<P: AsRef<std::path::Path>>(_path: P) -> Result<(), String> {
    Ok(())
}


/// Safely escapes an argument for the Windows command-line (CommandLineToArgvW inverse)
pub fn escape_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg.contains(' ') && !arg.contains('\t') && !arg.contains('\n') && !arg.contains('\r') && !arg.contains('\"') {
        return arg.to_string();
    }

    let mut out = String::from("\"");
    let mut backslashes = 0;

    for c in arg.chars() {
        if c == '\\' {
            backslashes += 1;
        } else if c == '\"' {
            out.push_str(&"\\".repeat(backslashes * 2 + 1));
            backslashes = 0;
            out.push('\"');
        } else {
            out.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
            out.push(c);
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('\"');
    out
}

/// Relaunches the current executable requesting UAC elevation
#[cfg(windows)]
pub fn elevate_and_relaunch() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;

    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    let exe_wide: Vec<u16> = OsStr::new(&current_exe).encode_wide().chain(std::iter::once(0)).collect();
    let params_str = args.iter().map(|a| escape_windows_arg(a)).collect::<Vec<_>>().join(" ");
    let params_wide: Vec<u16> = OsStr::new(&params_str).encode_wide().chain(std::iter::once(0)).collect();
    let runas_wide: Vec<u16> = OsStr::new("runas").encode_wide().chain(std::iter::once(0)).collect();

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: usize,
            lpOperation: *const u16,
            lpFile: *const u16,
            lpParameters: *const u16,
            lpDirectory: *const u16,
            nShowCmd: i32,
        ) -> usize;
    }

    const SW_SHOWNORMAL: i32 = 1;
    let res = unsafe {
        ShellExecuteW(
            0,
            runas_wide.as_ptr(),
            exe_wide.as_ptr(),
            if args.is_empty() { std::ptr::null() } else { params_wide.as_ptr() },
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };

    if res > 32 {
        std::process::exit(0);
    } else {
        Err(format!("UAC elevation request failed or was cancelled by user (code {})", res))
    }
}

/// Suppresses WSAECONNRESET (error 10054) on UDP sockets when remote port is unreachable
#[cfg(windows)]
pub fn disable_udp_connreset(socket: &UdpSocket) {
    const SIO_UDP_CONNRESET: u32 = 0x9800000C;
    let handle = socket.as_raw_socket();
    let mut flag: u32 = 0;
    let mut bytes_returned: u32 = 0;

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAIoctl(
            s: usize,
            dwIoControlCode: u32,
            lpvInBuffer: *const u32,
            cbInBuffer: u32,
            lpvOutBuffer: *mut u32,
            cbOutBuffer: u32,
            lpcbBytesReturned: *mut u32,
            lpOverlapped: *mut std::ffi::c_void,
            lpCompletionRoutine: *mut std::ffi::c_void,
        ) -> i32;
    }

    unsafe {
        WSAIoctl(
            handle as usize,
            SIO_UDP_CONNRESET,
            &mut flag,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}

#[cfg(not(windows))]
pub fn disable_udp_connreset(_socket: &UdpSocket) {}

#[cfg(not(windows))]
pub fn bind_socket_to_physical_interface(_socket: &UdpSocket, _target: &SocketAddr) -> Result<u32, String> {
    Ok(0)
}

#[cfg(not(windows))]
pub fn get_best_route_gateway(_target_ip: Ipv4Addr) -> Option<(Ipv4Addr, u32)> {
    None
}

#[cfg(not(windows))]
pub fn is_admin() -> bool {
    true
}

#[cfg(not(windows))]
pub fn elevate_and_relaunch() -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
pub fn set_interface_mtu(_if_index: u32, _mtu: u32) -> Result<(), String> { Ok(()) }
#[cfg(not(windows))]
pub fn add_unicast_ip(_if_index: u32, _ip: IpAddr, _prefix_len: u8) -> Result<(), String> { Ok(()) }
#[cfg(not(windows))]
pub fn add_ip_route(_if_index: u32, _dest: IpAddr, _prefix_len: u8, _next_hop: Option<IpAddr>, _metric: u32) -> Result<(), String> { Ok(()) }
#[cfg(not(windows))]
pub fn delete_ip_route(_if_index: u32, _dest: IpAddr, _prefix_len: u8, _next_hop: Option<IpAddr>) -> Result<(), String> { Ok(()) }
#[cfg(not(windows))]
pub fn set_interface_dns(_guid_u128: u128, _dns_servers: &[IpAddr]) -> Result<(), String> { Ok(()) }

// -------------------------------------------------------------------------------------------------
// Win32 IP Helper & NetIO API (pure in-process C calls, zero processes spawned, zero console windows)
// -------------------------------------------------------------------------------------------------

#[cfg(windows)]
const AF_INET: u16 = 2;
#[cfg(windows)]
const AF_INET6: u16 = 23;

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone)]
pub union SockAddrInet {
    pub si_family: u16,
    pub ipv4: SockAddrIn,
    pub ipv6: SockAddrIn6,
    pub raw: [u8; 28],
}

#[cfg(windows)]
impl Default for SockAddrInet {
    fn default() -> Self {
        Self { raw: [0u8; 28] }
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SockAddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

#[cfg(windows)]
impl SockAddrInet {
    pub fn from_ip(ip: IpAddr) -> Self {
        let mut sa = SockAddrInet::default();
        match ip {
            IpAddr::V4(v4) => {
                sa.ipv4 = SockAddrIn {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: u32::from_ne_bytes(v4.octets()),
                    sin_zero: [0u8; 8],
                };
            }
            IpAddr::V6(v6) => {
                sa.ipv6 = SockAddrIn6 {
                    sin6_family: AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: v6.octets(),
                    sin6_scope_id: 0,
                };
            }
        }
        sa
    }

    pub fn unspecified(is_v6: bool) -> Self {
        let mut sa = SockAddrInet::default();
        sa.si_family = if is_v6 { AF_INET6 } else { AF_INET };
        sa
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct IpAddressPrefix {
    pub prefix: SockAddrInet,
    pub prefix_length: u8,
    pub _pad: [u8; 3],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct MibIpForwardRow2 {
    pub interface_luid: u64,
    pub interface_index: u32,
    pub destination_prefix: IpAddressPrefix,
    pub next_hop: SockAddrInet,
    pub site_prefix_length: u8,
    pub _pad: [u8; 3],
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub metric: u32,
    pub protocol: i32,
    pub loopback: u8,
    pub autoconfigure_address: u8,
    pub publish: u8,
    pub immortal: u8,
    pub age: u32,
    pub origin: i32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct MibUnicastIpAddressRow {
    pub address: SockAddrInet,
    pub _pad0: [u8; 4],
    pub interface_luid: u64,
    pub interface_index: u32,
    pub prefix_origin: i32,
    pub suffix_origin: i32,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub on_link_prefix_length: u8,
    pub skip_as_source: u8,
    pub _pad1: [u8; 2],
    pub dad_state: i32,
    pub scope_id: i32,
    pub creation_time_stamp: i64,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MibIpInterfaceRow {
    pub family: u16,
    pub _pad0: [u8; 6],
    pub interface_luid: u64,
    pub interface_index: u32,
    pub max_reassembly_size: u32,
    pub interface_identifier: u64,
    pub min_router_advertisement_interval: u32,
    pub max_router_advertisement_interval: u32,
    pub advertising_enabled: u8,
    pub forwarding_enabled: u8,
    pub weak_host_send: u8,
    pub weak_host_receive: u8,
    pub use_automatic_metric: u8,
    pub use_neighbor_unreachability_detection: u8,
    pub managed_address_configuration_supported: u8,
    pub other_stateful_configuration_supported: u8,
    pub advertise_default_route: u8,
    pub _pad1: [u8; 3],
    pub router_discovery_behavior: i32,
    pub dad_transmits: u32,
    pub base_reachable_time: u32,
    pub retransmit_time: u32,
    pub path_mtu_discovery_timeout: u32,
    pub link_local_address_behavior: i32,
    pub link_local_address_timeout: u32,
    pub zone_indices: [u32; 32],
    pub site_prefix_length: u32,
    pub metric: u32,
    pub nl_mtu: u32,
    pub connected: u8,
    pub supports_wake_on_lan: u8,
    pub supports_directed_mac_wol: u8,
    pub supports_neighbor_discovery: u8,
    pub header_inclusion: u8,
    pub _pad2: [u8; 3],
    pub default_hop_limit: i32,
    pub metric_interval: u32,
    pub reassembly_timeout: u32,
}

#[cfg(windows)]
impl Default for MibIpInterfaceRow {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct DnsInterfaceSettings {
    version: u32,
    flags: u64,
    name_server: *const u16,
    domain: *const u16,
    search_list: *const u16,
    registration_enabled: u32,
    register_adapter_name: u32,
    enable_llmnr: u32,
    query_adapter_name: u32,
    profile_name_server: *const u16,
}

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn InitializeIpInterfaceEntry(row: *mut MibIpInterfaceRow);
    fn GetIpInterfaceEntry(row: *mut MibIpInterfaceRow) -> u32;
    fn SetIpInterfaceEntry(row: *mut MibIpInterfaceRow) -> u32;

    fn InitializeUnicastIpAddressEntry(row: *mut MibUnicastIpAddressRow);
    fn CreateUnicastIpAddressEntry(row: *const MibUnicastIpAddressRow) -> u32;
    #[allow(dead_code)]
    fn DeleteUnicastIpAddressEntry(row: *const MibUnicastIpAddressRow) -> u32;

    fn InitializeIpForwardEntry(row: *mut MibIpForwardRow2);
    fn CreateIpForwardEntry2(row: *const MibIpForwardRow2) -> u32;
    fn DeleteIpForwardEntry2(row: *const MibIpForwardRow2) -> u32;

    fn SetInterfaceDnsSettings(
        interface: windows_sys::core::GUID,
        settings: *const DnsInterfaceSettings,
    ) -> u32;
}

#[cfg(windows)]
pub fn set_interface_mtu(if_index: u32, mtu: u32) -> Result<(), String> {
    for family in [AF_INET, AF_INET6] {
        let mut row = MibIpInterfaceRow::default();
        unsafe {
            InitializeIpInterfaceEntry(&mut row);
            row.family = family;
            row.interface_index = if_index;
            if GetIpInterfaceEntry(&mut row) == 0 {
                row.nl_mtu = mtu;
                row.use_automatic_metric = 0;
                row.metric = 1; // Highest priority for VPN adapter to suppress DNS and route leaks
                let _ = SetIpInterfaceEntry(&mut row);
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn add_unicast_ip(if_index: u32, ip: IpAddr, prefix_len: u8) -> Result<(), String> {
    let mut row = MibUnicastIpAddressRow::default();
    unsafe {
        InitializeUnicastIpAddressEntry(&mut row);
        row.address = SockAddrInet::from_ip(ip);
        row.interface_index = if_index;
        row.on_link_prefix_length = prefix_len;
        let res = CreateUnicastIpAddressEntry(&row);
        // 0 = NO_ERROR, 5010 = ERROR_OBJECT_ALREADY_EXISTS
        if res != 0 && res != 5010 {
            return Err(format!("CreateUnicastIpAddressEntry failed: error code {}", res));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn add_ip_route(
    if_index: u32,
    dest: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
    metric: u32,
) -> Result<(), String> {
    let _ = delete_ip_route(if_index, dest, prefix_len, next_hop);

    let mut row = MibIpForwardRow2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
        row.interface_index = if_index;
        row.destination_prefix.prefix = SockAddrInet::from_ip(dest);
        row.destination_prefix.prefix_length = prefix_len;
        if let Some(gw) = next_hop {
            row.next_hop = SockAddrInet::from_ip(gw);
        } else {
            row.next_hop = SockAddrInet::unspecified(dest.is_ipv6());
        }
        row.metric = metric;
        let res = CreateIpForwardEntry2(&row);
        if res != 0 && res != 5010 {
            return Err(format!("CreateIpForwardEntry2 failed: error code {}", res));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn delete_ip_route(
    if_index: u32,
    dest: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
) -> Result<(), String> {
    let mut row = MibIpForwardRow2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
        row.interface_index = if_index;
        row.destination_prefix.prefix = SockAddrInet::from_ip(dest);
        row.destination_prefix.prefix_length = prefix_len;
        if let Some(gw) = next_hop {
            row.next_hop = SockAddrInet::from_ip(gw);
        } else {
            row.next_hop = SockAddrInet::unspecified(dest.is_ipv6());
        }
        let res = DeleteIpForwardEntry2(&row);
        if res == 0 || res == 1168 {
            Ok(())
        } else {
            Err(format!("DeleteIpForwardEntry2 failed: error code {}", res))
        }
    }
}

#[cfg(windows)]
pub fn set_interface_dns(guid_u128: u128, dns_servers: &[IpAddr]) -> Result<(), String> {
    if dns_servers.is_empty() {
        return Ok(());
    }

    let dns_str = dns_servers.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",");
    let dns_wide: Vec<u16> = dns_str.encode_utf16().chain(std::iter::once(0)).collect();

    let settings = DnsInterfaceSettings {
        version: 1, // DNS_INTERFACE_SETTINGS_VERSION1
        flags: 0x0001, // DNS_SETTING_NAMESERVER
        name_server: dns_wide.as_ptr(),
        domain: std::ptr::null(),
        search_list: std::ptr::null(),
        registration_enabled: 0,
        register_adapter_name: 0,
        enable_llmnr: 0,
        query_adapter_name: 0,
        profile_name_server: std::ptr::null(),
    };

    let guid = windows_sys::core::GUID::from_u128(guid_u128);
    let res = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    if res == 0 {
        Ok(())
    } else {
        Err(format!("SetInterfaceDnsSettings failed with code {}", res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_windows_arg() {
        assert_eq!(escape_windows_arg("simple"), "simple");
        assert_eq!(escape_windows_arg(""), "\"\"");
        assert_eq!(escape_windows_arg("hello world"), "\"hello world\"");
        assert_eq!(escape_windows_arg(r#"foo"bar"#), r#""foo\"bar""#);
        assert_eq!(escape_windows_arg(r#"C:\Path\To\"#), r#"C:\Path\To\"#);
        assert_eq!(escape_windows_arg(r#"C:\Path With Spaces\"#), r#""C:\Path With Spaces\\""#);
    }

    #[test]
    fn test_is_admin_runs_without_panic() {
        // Must execute cleanly and return boolean without error
        let admin = is_admin();
        println!("Process elevated admin status: {}", admin);
    }

    #[test]
    fn test_set_file_owner_only_acl() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("phobos_test_acl.tmp");
        std::fs::write(&test_file, b"secret content").expect("failed to write test file");
        let res = set_file_owner_only_acl(&test_file);
        let _ = std::fs::remove_file(&test_file);
        assert!(res.is_ok(), "set_file_owner_only_acl must succeed on created file");
    }
}


