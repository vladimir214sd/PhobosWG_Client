// Native Win32 GUI for Phobos WireGuard Client for Windows
// Zero GPU/heavy runtime dependencies for minimal executable size (~1.5 MB)

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::Arc;

use base64::Engine;
use boringtun::x25519::{PublicKey, StaticSecret};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::DataExchange::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::UI::Controls::Dialogs::*;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::HiDpi::*;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::archive::PhobosProfile;
use crate::profile_store::{delete_profile, import_profile, load_all_profiles};
use crate::tunnel_service::{TunnelService, TunnelStatus};

const ID_TAB_CONTROL: usize = 1001;
const ID_LIST_TUNNELS: usize = 1002;
const ID_BTN_ADD: usize = 1003;
const ID_BTN_DELETE: usize = 1004;

const ID_GRP_INTERFACE: usize = 1010;
const ID_BTN_COPY_PUBKEY: usize = 1015;
const ID_BTN_TOGGLE: usize = 1022;

const ID_GRP_PEER: usize = 1030;

// Log Tab Controls
const ID_BTN_COPY_LOGS: usize = 1051;
const ID_BTN_CLEAR_LOGS: usize = 1052;
const ID_TXT_LOGS: usize = 1053;

const TIMER_STATS_ID: usize = 1;
const CF_UNICODETEXT: u32 = 13;

#[inline]
fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn set_window_text(hwnd: HWND, text: &str) {
    let wide = to_wide(text);
    SetWindowTextW(hwnd, wide.as_ptr());
}

unsafe fn set_clipboard_text(hwnd: HWND, text: &str) {
    let wide = to_wide(text);
    let bytes_len = wide.len() * 2;
    let hmem = GlobalAlloc(GMEM_MOVEABLE, bytes_len);
    if hmem.is_null() {
        return;
    }
    let ptr = GlobalLock(hmem) as *mut u16;
    if !ptr.is_null() {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
        GlobalUnlock(hmem);
        if OpenClipboard(hwnd) != 0 {
            EmptyClipboard();
            if SetClipboardData(CF_UNICODETEXT, hmem as _).is_null() {
                GlobalFree(hmem);
            }
            CloseClipboard();
        } else {
            GlobalFree(hmem);
        }
    } else {
        GlobalFree(hmem);
    }
}

unsafe fn open_file_dialog(hwnd: HWND) -> Option<std::path::PathBuf> {
    let mut file_buf = [0u16; 1024];
    let filter: Vec<u16> = "Пакеты Phobos (*.tar.gz;*.tgz;*.conf)\0*.tar.gz;*.tgz;*.conf\0Все файлы (*.*)\0*.*\0\0"
        .encode_utf16()
        .collect();

    let mut ofn: OPENFILENAMEW = std::mem::zeroed();
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.lpstrFile = file_buf.as_mut_ptr();
    ofn.nMaxFile = file_buf.len() as u32;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if GetOpenFileNameW(&mut ofn) != 0 {
        use std::os::windows::ffi::OsStringExt;
        let len = file_buf.iter().position(|&c| c == 0).unwrap_or(file_buf.len());
        let os_str = std::ffi::OsString::from_wide(&file_buf[..len]);
        Some(std::path::PathBuf::from(os_str))
    } else {
        None
    }
}

unsafe fn create_control(
    class: &[u16],
    title: &str,
    style: u32,
    ex_style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    parent: HWND,
    id: usize,
    font: HFONT,
) -> HWND {
    let title_w = to_wide(title);
    let hinst = GetModuleHandleW(null());
    let hctl = CreateWindowExW(
        ex_style,
        class.as_ptr(),
        title_w.as_ptr(),
        style,
        x, y, w, h,
        parent,
        id as isize as HMENU,
        hinst,
        null(),
    );
    if !font.is_null() && !hctl.is_null() {
        SendMessageW(hctl, WM_SETFONT, font as WPARAM, 1);
    }
    hctl
}

struct AppState {
    service: Arc<TunnelService>,
    profiles: Vec<PhobosProfile>,
    selected_index: Option<usize>,
    current_tab: usize,
    hfont: HFONT,
    hfont_bold: HFONT,
    hfont_mono: HFONT,

    hwnd_tab: HWND,
    hwnd_list: HWND,
    hwnd_btn_add: HWND,
    hwnd_btn_delete: HWND,

    hwnd_grp_interface: HWND,
    hwnd_val_status: HWND,
    hwnd_val_pubkey: HWND,
    hwnd_btn_copy_pubkey: HWND,
    hwnd_val_mtu: HWND,
    hwnd_val_ips: HWND,
    hwnd_val_dns: HWND,
    hwnd_btn_toggle: HWND,

    hwnd_grp_peer: HWND,
    hwnd_val_peer_pubkey: HWND,
    hwnd_val_psk: HWND,
    hwnd_val_allowed_ips: HWND,
    hwnd_val_endpoint: HWND,
    hwnd_val_traffic: HWND,
    hwnd_val_handshake: HWND,

    tunnel_controls: Vec<HWND>,

    hwnd_lbl_logs: HWND,
    hwnd_btn_copy_logs: HWND,
    hwnd_btn_clear_logs: HWND,
    hwnd_txt_logs: HWND,
    log_controls: Vec<HWND>,

    last_log_count: usize,
    current_pubkey_copy: String,
}

impl AppState {
    fn reload_profiles(&mut self) {
        self.profiles = load_all_profiles();
        if self.profiles.is_empty() {
            self.selected_index = None;
        } else if let Some(sel) = self.selected_index {
            if sel >= self.profiles.len() {
                self.selected_index = Some(self.profiles.len() - 1);
            }
        } else {
            self.selected_index = Some(0);
        }
    }

    unsafe fn update_listbox(&mut self) {
        SendMessageW(self.hwnd_list, LB_RESETCONTENT, 0, 0);
        for profile in &self.profiles {
            let wide = to_wide(&profile.client_name);
            SendMessageW(self.hwnd_list, LB_ADDSTRING, 0, wide.as_ptr() as isize);
        }
        if let Some(sel) = self.selected_index {
            SendMessageW(self.hwnd_list, LB_SETCURSEL, sel, 0);
        } else {
            SendMessageW(self.hwnd_list, LB_SETCURSEL, (-1isize) as usize, 0);
        }
    }

    unsafe fn update_details(&mut self) {
        if let Some(idx) = self.selected_index {
            if idx < self.profiles.len() {
                let profile = &self.profiles[idx];
                let is_active = self.service.active_profile_name.lock().unwrap().as_deref() == Some(&profile.client_name);
                let current_status = self.service.status.lock().unwrap().clone();

                set_window_text(self.hwnd_grp_interface, &format!("Интерфейс: {}", profile.client_name));

                // Status string
                let status_str = if is_active {
                    match current_status {
                        TunnelStatus::Connected => "● Подключен",
                        TunnelStatus::Connecting => "◌ Подключение...",
                        TunnelStatus::Error(ref e) => e.as_str(),
                        TunnelStatus::Disconnected => "○ Отключен",
                    }
                } else {
                    "○ Отключен"
                };
                set_window_text(self.hwnd_val_status, status_str);

                // WireGuard parsed config
                let wg_conf = profile.parse_wg_config().ok();

                let client_pubkey_b64 = wg_conf.as_ref().map(|c| {
                    use zeroize::Zeroize;
                    let mut key_bytes = c.private_key;
                    let secret = StaticSecret::from(key_bytes);
                    let pubkey = PublicKey::from(&secret);
                    key_bytes.zeroize();
                    base64::engine::general_purpose::STANDARD.encode(pubkey.as_bytes())
                }).unwrap_or_else(|| "---".to_string());
                self.current_pubkey_copy = client_pubkey_b64.clone();
                set_window_text(self.hwnd_val_pubkey, &client_pubkey_b64);

                let mtu_str = wg_conf.as_ref().map(|c| c.mtu.to_string()).unwrap_or_else(|| "1280".to_string());
                set_window_text(self.hwnd_val_mtu, &mtu_str);

                let ips_str = if let Some(ref c) = wg_conf {
                    let mut s = format!("{}/{}", c.client_ipv4, c.client_ipv4_prefix);
                    if let Some(v6) = c.client_ipv6 {
                        s.push_str(&format!(", {}/128", v6));
                    }
                    s
                } else {
                    "---".to_string()
                };
                set_window_text(self.hwnd_val_ips, &ips_str);

                let dns_str = wg_conf.as_ref().map(|c| {
                    c.dns_servers.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ")
                }).unwrap_or_else(|| "8.8.8.8, 1.1.1.1".to_string());
                set_window_text(self.hwnd_val_dns, &dns_str);

                // Button Connect/Disconnect
                if is_active && current_status != TunnelStatus::Disconnected {
                    set_window_text(self.hwnd_btn_toggle, "Отключить");
                } else {
                    set_window_text(self.hwnd_btn_toggle, "Подключить");
                }

                // Peer details
                let peer_pubkey_b64 = wg_conf.as_ref().map(|c| {
                    base64::engine::general_purpose::STANDARD.encode(&c.peer_public_key)
                }).unwrap_or_else(|| "---".to_string());
                set_window_text(self.hwnd_val_peer_pubkey, &peer_pubkey_b64);

                let psk_str = if wg_conf.as_ref().and_then(|c| c.preshared_key).is_some() {
                    "включено"
                } else {
                    "отключено"
                };
                set_window_text(self.hwnd_val_psk, psk_str);
                set_window_text(self.hwnd_val_allowed_ips, "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1");
                set_window_text(self.hwnd_val_endpoint, &format!("{} ({})", profile.target, profile.masking));

                // Traffic stats
                if is_active && current_status == TunnelStatus::Connected {
                    let stats = self.service.stats.lock().unwrap().clone();
                    let sent_mb = stats.bytes_sent as f64 / (1024.0 * 1024.0);
                    let recv_mb = stats.bytes_recv as f64 / (1024.0 * 1024.0);
                    let traf_str = format!("↑ {:.1} KB/s ({:.2} MB)  |  ↓ {:.1} KB/s ({:.2} MB)",
                        stats.rate_sent_kbps, sent_mb, stats.rate_recv_kbps, recv_mb);
                    set_window_text(self.hwnd_val_traffic, &traf_str);

                    let hs_str = if let Some(secs) = stats.last_handshake_secs {
                        format!("{} сек. назад", secs)
                    } else {
                        "выполняется...".to_string()
                    };
                    set_window_text(self.hwnd_val_handshake, &hs_str);
                } else {
                    set_window_text(self.hwnd_val_traffic, "---");
                    set_window_text(self.hwnd_val_handshake, "---");
                }
                return;
            }
        }

        // Empty state
        set_window_text(self.hwnd_grp_interface, "Интерфейс: (нет выбранного)");
        set_window_text(self.hwnd_val_status, "Нет активного туннеля");
        set_window_text(self.hwnd_val_pubkey, "---");
        set_window_text(self.hwnd_val_mtu, "---");
        set_window_text(self.hwnd_val_ips, "---");
        set_window_text(self.hwnd_val_dns, "---");
        set_window_text(self.hwnd_val_peer_pubkey, "---");
        set_window_text(self.hwnd_val_psk, "---");
        set_window_text(self.hwnd_val_allowed_ips, "---");
        set_window_text(self.hwnd_val_endpoint, "---");
        set_window_text(self.hwnd_val_traffic, "---");
        set_window_text(self.hwnd_val_handshake, "---");
        set_window_text(self.hwnd_btn_toggle, "Подключить");
    }

    unsafe fn switch_tab(&mut self, new_tab: usize) {
        self.current_tab = new_tab;
        let show_tunnels = if new_tab == 0 { SW_SHOW } else { SW_HIDE };
        let show_logs = if new_tab == 1 { SW_SHOW } else { SW_HIDE };

        for &hwnd in &self.tunnel_controls {
            ShowWindow(hwnd, show_tunnels);
        }
        for &hwnd in &self.log_controls {
            ShowWindow(hwnd, show_logs);
        }

        if new_tab == 1 {
            self.update_logs();
        }
    }

    unsafe fn update_logs(&mut self) {
        let logs_guard = match self.service.logs.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if logs_guard.len() != self.last_log_count {
            self.last_log_count = logs_guard.len();
            let joined = logs_guard.join("\r\n");
            drop(logs_guard);
            set_window_text(self.hwnd_txt_logs, &joined);
            SendMessageW(self.hwnd_txt_logs, EM_SETSEL, joined.len() as usize, joined.len() as isize);
            SendMessageW(self.hwnd_txt_logs, EM_SCROLLCARET, 0, 0);
        }
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState;

    match msg {
        WM_CREATE => {
            let cs = &*(lparam as *const CREATESTRUCTW);
            let state = &mut *(cs.lpCreateParams as *mut AppState);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as *mut _ as isize);

            let tab_class = to_wide("SysTabControl32");
            let static_class = to_wide("STATIC");
            let btn_class = to_wide("BUTTON");
            let list_class = to_wide("LISTBOX");
            let edit_class = to_wide("EDIT");

            // 1. Top Tab Control
            state.hwnd_tab = create_control(
                &tab_class, "",
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                0, 10, 10, 724, 495, hwnd, ID_TAB_CONTROL, state.hfont
            );

            // Add tabs: "Туннели" & "Журнал"
            let tab_tunnels = to_wide("  Туннели  ");
            let mut tc_item: TCITEMW = std::mem::zeroed();
            tc_item.mask = TCIF_TEXT;
            tc_item.pszText = tab_tunnels.as_ptr() as *mut u16;
            SendMessageW(state.hwnd_tab, TCM_INSERTITEMW, 0, &tc_item as *const _ as LPARAM);

            let tab_logs = to_wide("  Журнал  ");
            tc_item.pszText = tab_logs.as_ptr() as *mut u16;
            SendMessageW(state.hwnd_tab, TCM_INSERTITEMW, 1, &tc_item as *const _ as LPARAM);

            // 2. Left Column (Tunnels List)
            let lbl_list = create_control(&static_class, "Туннели:", WS_CHILD | WS_VISIBLE, 0, 24, 46, 120, 18, hwnd, 0, state.hfont);
            state.tunnel_controls.push(lbl_list);

            state.hwnd_list = create_control(
                &list_class, "",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP | (LBS_NOTIFY as u32) | (LBS_OWNERDRAWFIXED as u32) | (LBS_HASSTRINGS as u32),
                WS_EX_CLIENTEDGE,
                24, 68, 206, 380, hwnd, ID_LIST_TUNNELS, state.hfont
            );
            SendMessageW(state.hwnd_list, LB_SETITEMHEIGHT, 0, 26);
            state.tunnel_controls.push(state.hwnd_list);

            state.hwnd_btn_add = create_control(
                &btn_class, "➕ Добавить",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
                0, 24, 458, 120, 30, hwnd, ID_BTN_ADD, state.hfont
            );
            state.tunnel_controls.push(state.hwnd_btn_add);

            state.hwnd_btn_delete = create_control(
                &btn_class, "❌ Удалить",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
                0, 148, 458, 82, 30, hwnd, ID_BTN_DELETE, state.hfont
            );
            state.tunnel_controls.push(state.hwnd_btn_delete);

            // 3. Right Column: Interface Group
            state.hwnd_grp_interface = create_control(
                &btn_class, "Интерфейс: 123",
                WS_CHILD | WS_VISIBLE | (BS_GROUPBOX as u32),
                0, 244, 44, 474, 206, hwnd, ID_GRP_INTERFACE, state.hfont_bold
            );
            state.tunnel_controls.push(state.hwnd_grp_interface);

            let make_label = |title: &str, x: i32, y: i32, w: i32, h: i32, font: HFONT, controls: &mut Vec<HWND>| -> HWND {
                let hctl = create_control(&static_class, title, WS_CHILD | WS_VISIBLE, 0, x, y, w, h, hwnd, 0, font);
                controls.push(hctl);
                hctl
            };

            make_label("Статус:", 260, 68, 110, 18, state.hfont_bold, &mut state.tunnel_controls);
            state.hwnd_val_status = make_label("○ Отключен", 375, 68, 330, 18, state.hfont_bold, &mut state.tunnel_controls);

            make_label("Публичный ключ:", 260, 92, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_pubkey = make_label("---", 375, 92, 260, 18, state.hfont_mono, &mut state.tunnel_controls);

            state.hwnd_btn_copy_pubkey = create_control(
                &btn_class, "📋",
                WS_CHILD | WS_VISIBLE | (BS_PUSHBUTTON as u32),
                0, 640, 89, 32, 22, hwnd, ID_BTN_COPY_PUBKEY, state.hfont
            );
            state.tunnel_controls.push(state.hwnd_btn_copy_pubkey);

            make_label("MTU:", 260, 116, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_mtu = make_label("1280", 375, 116, 330, 18, state.hfont, &mut state.tunnel_controls);

            make_label("IP-адреса:", 260, 140, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_ips = make_label("---", 375, 140, 330, 18, state.hfont, &mut state.tunnel_controls);

            make_label("DNS-серверы:", 260, 164, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_dns = make_label("---", 375, 164, 330, 18, state.hfont, &mut state.tunnel_controls);

            state.hwnd_btn_toggle = create_control(
                &btn_class, "Подключить",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
                0, 260, 196, 130, 32, hwnd, ID_BTN_TOGGLE, state.hfont_bold
            );
            state.tunnel_controls.push(state.hwnd_btn_toggle);

            // 4. Right Column: Peer Group
            state.hwnd_grp_peer = create_control(
                &btn_class, "Пир",
                WS_CHILD | WS_VISIBLE | (BS_GROUPBOX as u32),
                0, 244, 258, 474, 230, hwnd, ID_GRP_PEER, state.hfont_bold
            );
            state.tunnel_controls.push(state.hwnd_grp_peer);

            make_label("Публичный ключ:", 260, 280, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_peer_pubkey = make_label("---", 375, 280, 330, 18, state.hfont_mono, &mut state.tunnel_controls);

            make_label("Общий ключ:", 260, 304, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_psk = make_label("отключено", 375, 304, 330, 18, state.hfont, &mut state.tunnel_controls);

            make_label("Разрешенные IP:", 260, 328, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_allowed_ips = make_label("0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1", 375, 328, 330, 18, state.hfont, &mut state.tunnel_controls);

            make_label("Сервер (Endpoint):", 260, 352, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_endpoint = make_label("---", 375, 352, 330, 18, state.hfont, &mut state.tunnel_controls);

            make_label("Передача данных:", 260, 376, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_traffic = make_label("---", 375, 376, 330, 18, state.hfont, &mut state.tunnel_controls);

            make_label("Рукопожатие:", 260, 400, 110, 18, state.hfont, &mut state.tunnel_controls);
            state.hwnd_val_handshake = make_label("---", 375, 400, 330, 18, state.hfont, &mut state.tunnel_controls);

            // 5. Tab 2 Controls (Logs)
            state.hwnd_lbl_logs = make_label("Журнал событий:", 24, 46, 200, 20, state.hfont_bold, &mut state.log_controls);

            state.hwnd_btn_copy_logs = create_control(
                &btn_class, "📋 Копировать всё",
                WS_CHILD | (BS_PUSHBUTTON as u32),
                0, 520, 42, 120, 26, hwnd, ID_BTN_COPY_LOGS, state.hfont
            );
            state.log_controls.push(state.hwnd_btn_copy_logs);

            state.hwnd_btn_clear_logs = create_control(
                &btn_class, "🗑 Очистить",
                WS_CHILD | (BS_PUSHBUTTON as u32),
                0, 646, 42, 72, 26, hwnd, ID_BTN_CLEAR_LOGS, state.hfont
            );
            state.log_controls.push(state.hwnd_btn_clear_logs);

            state.hwnd_txt_logs = create_control(
                &edit_class, "",
                WS_CHILD | WS_VSCROLL | WS_HSCROLL | (ES_MULTILINE as u32) | (ES_READONLY as u32) | (ES_AUTOVSCROLL as u32),
                WS_EX_CLIENTEDGE,
                24, 74, 694, 414, hwnd, ID_TXT_LOGS, state.hfont_mono
            );
            state.log_controls.push(state.hwnd_txt_logs);

            // Hide logs by default (Tab 0 is active)
            for &h in &state.log_controls {
                ShowWindow(h, SW_HIDE);
            }

            // Enable Drag & Drop
            DragAcceptFiles(hwnd, 1);

            // Populate initial list & details
            state.update_listbox();
            state.update_details();

            // Set refresh timer (500ms)
            SetTimer(hwnd, TIMER_STATS_ID, 500, None);
            0
        }

        WM_COMMAND => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            let id = (wparam & 0xFFFF) as usize;
            let code = ((wparam >> 16) & 0xFFFF) as u16;

            match id {
                ID_LIST_TUNNELS if code == LBN_SELCHANGE as u16 => {
                    let cur = SendMessageW(state.hwnd_list, LB_GETCURSEL, 0, 0);
                    if cur != -1 {
                        state.selected_index = Some(cur as usize);
                        state.update_details();
                    }
                }
                ID_BTN_ADD => {
                    if let Some(path) = open_file_dialog(hwnd) {
                        if let Ok(profile) = import_profile(&path) {
                            state.reload_profiles();
                            if let Some(pos) = state.profiles.iter().position(|p| p.client_name == profile.client_name) {
                                state.selected_index = Some(pos);
                            }
                            state.update_listbox();
                            state.update_details();
                            InvalidateRect(state.hwnd_list, null(), 1);
                        }
                    }
                }
                ID_BTN_DELETE => {
                    if let Some(idx) = state.selected_index {
                        if idx < state.profiles.len() {
                            let name = state.profiles[idx].client_name.clone();
                            let active_name = state.service.active_profile_name.lock().unwrap().clone();
                            if active_name.as_deref() == Some(&name) {
                                state.service.stop();
                            }
                            let _ = delete_profile(&name);
                            state.reload_profiles();
                            state.update_listbox();
                            state.update_details();
                            InvalidateRect(state.hwnd_list, null(), 1);
                        }
                    }
                }
                ID_BTN_TOGGLE => {
                    if let Some(idx) = state.selected_index {
                        if idx < state.profiles.len() {
                            let profile = state.profiles[idx].clone();
                            let active_name = state.service.active_profile_name.lock().unwrap().clone();
                            let current_status = state.service.status.lock().unwrap().clone();

                            if active_name.as_deref() == Some(&profile.client_name) && current_status != TunnelStatus::Disconnected {
                                state.service.stop();
                            } else {
                                state.service.start(profile);
                            }
                            state.update_details();
                            InvalidateRect(state.hwnd_list, null(), 1);
                        }
                    }
                }
                ID_BTN_COPY_PUBKEY => {
                    if !state.current_pubkey_copy.is_empty() {
                        set_clipboard_text(hwnd, &state.current_pubkey_copy);
                    }
                }
                ID_BTN_COPY_LOGS => {
                    let logs = state.service.logs.lock().unwrap().join("\r\n");
                    set_clipboard_text(hwnd, &logs);
                }
                ID_BTN_CLEAR_LOGS => {
                    state.service.logs.lock().unwrap().clear();
                    state.last_log_count = 0;
                    set_window_text(state.hwnd_txt_logs, "");
                }
                _ => {}
            }
            0
        }

        WM_NOTIFY => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            let nmhdr = &*(lparam as *const NMHDR);
            if nmhdr.idFrom == ID_TAB_CONTROL && nmhdr.code == TCN_SELCHANGE {
                let cur = SendMessageW(state.hwnd_tab, TCM_GETCURSEL, 0, 0) as usize;
                state.switch_tab(cur);
            }
            0
        }

        WM_DRAWITEM => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let dis = &*(lparam as *const DRAWITEMSTRUCT);
            if dis.CtlID == ID_LIST_TUNNELS as u32 && dis.itemID != 0xFFFFFFFF {
                let state = &mut *state_ptr;
                let idx = dis.itemID as usize;
                let is_selected = (dis.itemState & ODS_SELECTED) != 0;

                if idx < state.profiles.len() {
                    let profile = &state.profiles[idx];
                    let active_name = state.service.active_profile_name.lock().unwrap().clone();
                    let is_active = active_name.as_deref() == Some(&profile.client_name);
                    let current_status = state.service.status.lock().unwrap().clone();

                    let bg_brush = if is_selected {
                        GetSysColorBrush(COLOR_HIGHLIGHT as i32)
                    } else {
                        GetSysColorBrush(COLOR_WINDOW as i32)
                    };
                    FillRect(dis.hDC, &dis.rcItem, bg_brush);

                    let dot_color = if is_active {
                        match current_status {
                            TunnelStatus::Connected => rgb(46, 204, 113),
                            TunnelStatus::Connecting => rgb(241, 196, 15),
                            _ => rgb(160, 160, 160),
                        }
                    } else {
                        rgb(180, 180, 180)
                    };

                    let dot_brush = CreateSolidBrush(dot_color);
                    let null_pen = GetStockObject(NULL_PEN as i32);
                    let old_brush = SelectObject(dis.hDC, dot_brush);
                    let old_pen = SelectObject(dis.hDC, null_pen);

                    let center_y = (dis.rcItem.top + dis.rcItem.bottom) / 2;
                    Ellipse(dis.hDC, dis.rcItem.left + 8, center_y - 5, dis.rcItem.left + 18, center_y + 5);

                    SelectObject(dis.hDC, old_brush);
                    SelectObject(dis.hDC, old_pen);
                    DeleteObject(dot_brush);

                    SetBkMode(dis.hDC, TRANSPARENT as i32);
                    SetTextColor(dis.hDC, if is_selected { rgb(255, 255, 255) } else { rgb(0, 0, 0) });
                    SelectObject(dis.hDC, state.hfont);

                    let mut text_rect = RECT {
                        left: dis.rcItem.left + 24,
                        top: dis.rcItem.top,
                        right: dis.rcItem.right - 4,
                        bottom: dis.rcItem.bottom,
                    };
                    let text_w = to_wide(&profile.client_name);
                    DrawTextW(dis.hDC, text_w.as_ptr(), text_w.len() as i32 - 1, &mut text_rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                }
                return 1;
            }
            0
        }

        WM_DROPFILES => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            let hdrop = wparam as HDROP;
            let count = DragQueryFileW(hdrop, 0xFFFFFFFF, null_mut(), 0);
            for i in 0..count {
                let mut buf = [0u16; 1024];
                let len = DragQueryFileW(hdrop, i, buf.as_mut_ptr(), buf.len() as u32);
                if len > 0 {
                    use std::os::windows::ffi::OsStringExt;
                    let os_str = std::ffi::OsString::from_wide(&buf[..len as usize]);
                    let path = std::path::PathBuf::from(os_str);
                    if let Ok(profile) = import_profile(&path) {
                        state.reload_profiles();
                        if let Some(pos) = state.profiles.iter().position(|p| p.client_name == profile.client_name) {
                            state.selected_index = Some(pos);
                        }
                        state.update_listbox();
                        state.update_details();
                    }
                }
            }
            DragFinish(hdrop);
            0
        }

        WM_TIMER => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            if wparam == TIMER_STATS_ID {
                if state.current_tab == 0 {
                    state.update_details();
                    InvalidateRect(state.hwnd_list, null(), 1);
                } else {
                    state.update_logs();
                }
            }
            0
        }

        WM_CLOSE => {
            if !state_ptr.is_null() {
                let state = &mut *state_ptr;
                if state.service.is_active() {
                    state.service.stop();
                    // Brief wait for background thread to restore routing table
                    std::thread::sleep(std::time::Duration::from_millis(300));
                }
            }
            DestroyWindow(hwnd);
            0
        }

        WM_DESTROY => {
            if !state_ptr.is_null() {
                let state = &mut *state_ptr;
                state.service.stop();
            }
            KillTimer(hwnd, TIMER_STATS_ID);
            PostQuitMessage(0);
            0
        }

        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Runs the native Win32 GUI application
pub fn run_gui() -> Result<(), String> {
    unsafe {
        // High-DPI awareness for crisp rendering on modern displays
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

        // Initialize Common Controls
        let mut icc: INITCOMMONCONTROLSEX = std::mem::zeroed();
        icc.dwSize = std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32;
        icc.dwICC = ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
        InitCommonControlsEx(&icc);

        let hinst = GetModuleHandleW(null());
        let class_name = to_wide("PhobosWireGuardWindowClass");
        let h_icon = LoadIconW(hinst, 1 as *const u16);

        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = Some(window_proc);
        wc.hInstance = hinst;
        wc.hIcon = h_icon;
        wc.hbrBackground = (COLOR_BTNFACE + 1) as HBRUSH;
        wc.lpszClassName = class_name.as_ptr();
        wc.hCursor = LoadCursorW(null_mut(), IDC_ARROW);

        RegisterClassW(&wc);

        // Create standard Segoe UI fonts
        let font_name = to_wide("Segoe UI");
        let font_mono_name = to_wide("Consolas");

        let hfont = CreateFontW(
            -13, 0, 0, 0, FW_NORMAL as i32, 0, 0, 0,
            DEFAULT_CHARSET as u32, OUT_DEFAULT_PRECIS as u32, CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32, (DEFAULT_PITCH | FF_DONTCARE) as u32, font_name.as_ptr()
        );
        let hfont_bold = CreateFontW(
            -13, 0, 0, 0, FW_BOLD as i32, 0, 0, 0,
            DEFAULT_CHARSET as u32, OUT_DEFAULT_PRECIS as u32, CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32, (DEFAULT_PITCH | FF_DONTCARE) as u32, font_name.as_ptr()
        );
        let hfont_mono = CreateFontW(
            -13, 0, 0, 0, FW_NORMAL as i32, 0, 0, 0,
            DEFAULT_CHARSET as u32, OUT_DEFAULT_PRECIS as u32, CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32, (DEFAULT_PITCH | FF_DONTCARE) as u32, font_mono_name.as_ptr()
        );

        let profiles = load_all_profiles();
        let selected_index = if !profiles.is_empty() { Some(0) } else { None };

        let mut app_state = Box::new(AppState {
            service: Arc::new(TunnelService::new()),
            profiles,
            selected_index,
            current_tab: 0,
            hfont,
            hfont_bold,
            hfont_mono,
            hwnd_tab: null_mut(),
            hwnd_list: null_mut(),
            hwnd_btn_add: null_mut(),
            hwnd_btn_delete: null_mut(),
            hwnd_grp_interface: null_mut(),
            hwnd_val_status: null_mut(),
            hwnd_val_pubkey: null_mut(),
            hwnd_btn_copy_pubkey: null_mut(),
            hwnd_val_mtu: null_mut(),
            hwnd_val_ips: null_mut(),
            hwnd_val_dns: null_mut(),
            hwnd_btn_toggle: null_mut(),
            hwnd_grp_peer: null_mut(),
            hwnd_val_peer_pubkey: null_mut(),
            hwnd_val_psk: null_mut(),
            hwnd_val_allowed_ips: null_mut(),
            hwnd_val_endpoint: null_mut(),
            hwnd_val_traffic: null_mut(),
            hwnd_val_handshake: null_mut(),
            tunnel_controls: Vec::new(),
            hwnd_lbl_logs: null_mut(),
            hwnd_btn_copy_logs: null_mut(),
            hwnd_btn_clear_logs: null_mut(),
            hwnd_txt_logs: null_mut(),
            log_controls: Vec::new(),
            last_log_count: 0,
            current_pubkey_copy: String::new(),
        });

        // Compute centered window rectangle
        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);
        let win_w = 760;
        let win_h = 555;
        let win_x = (screen_w - win_w) / 2;
        let win_y = (screen_h - win_h) / 2;

        let title = to_wide("Phobos WireGuard Client");
        let hwnd = CreateWindowExW(
            0, class_name.as_ptr(), title.as_ptr(),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
            win_x, win_y, win_w, win_h,
            null_mut(), null_mut(), hinst,
            app_state.as_mut() as *mut AppState as *mut c_void
        );

        if hwnd.is_null() {
            return Err("Failed to create main window".to_string());
        }

        const WM_SETICON: u32 = 0x0080;
        if !h_icon.is_null() {
            SendMessageW(hwnd, WM_SETICON, 1, h_icon as isize); // ICON_BIG = 1
            SendMessageW(hwnd, WM_SETICON, 0, h_icon as isize); // ICON_SMALL = 0
        }

        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        // Win32 Message Loop
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Final safety cleanup: ensure tunnel is stopped and routes restored
        if app_state.service.is_active() {
            app_state.service.stop();
            std::thread::sleep(std::time::Duration::from_millis(300));
        }

        // Cleanup
        DeleteObject(hfont);
        DeleteObject(hfont_bold);
        DeleteObject(hfont_mono);

        Ok(())
    }
}
