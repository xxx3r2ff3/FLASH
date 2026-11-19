#![windows_subsystem = "windows"]
#![allow(unsafe_op_in_unsafe_fn)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::Deserialize;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Dwm::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::*;

const CREATE_NO_WINDOW: u32 = 0x08000000;

const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

#[derive(Deserialize, Default)]
struct TrafficMessage {
    #[serde(default)]
    up: u64,
    #[serde(default)]
    down: u64,
}

#[derive(Deserialize, Default)]
struct ConnectionsResponse {
    #[serde(default)]
    connections: Vec<ConnectionItem>,
    #[serde(rename = "downloadTotal", default)]
    download_total: u64,
    #[serde(rename = "uploadTotal", default)]
    upload_total: u64,
    #[serde(default)]
    memory: u64,
}

#[derive(Deserialize, Default, Clone)]
struct ConnectionItem {
    #[serde(default)]
    id: String,
    #[serde(default)]
    metadata: MetadataItem,
    #[serde(default)]
    upload: u64,
    #[serde(default)]
    download: u64,
    #[serde(default)]
    chains: Vec<String>,
    #[serde(default)]
    rule: String,
    #[serde(rename = "rulePayload", default)]
    rule_payload: String,
    #[serde(default)]
    start: String,
    #[serde(skip)]
    start_epoch: u64,
    #[serde(skip)]
    duration_secs: u64,
    #[serde(skip)]
    is_active: bool,
    #[serde(skip)]
    prev_upload: u64,
    #[serde(skip)]
    prev_download: u64,
    #[serde(skip)]
    cur_up_speed: u64,
    #[serde(skip)]
    cur_down_speed: u64,
    #[serde(skip)]
    avg_speed: u64,
    #[serde(skip)]
    dl_ul_ratio: f32,
    #[serde(skip)]
    is_idle: bool,
}

#[derive(Deserialize, Default, Clone)]
struct MetadataItem {
    #[serde(default)]
    network: String,
    #[serde(rename = "type", default)]
    inbound_type: String,
    #[serde(default)]
    host: String,
    #[serde(rename = "destinationIP", default)]
    destination_ip: String,
    #[serde(rename = "destinationPort", default)]
    destination_port: String,
    #[serde(rename = "sourceIP", default)]
    source_ip: String,
    #[serde(rename = "sourcePort", default)]
    source_port: String,
}

#[derive(Deserialize, Default)]
struct SubscriptionsConfig {
    #[serde(default)]
    active: String,
    #[serde(default)]
    subscriptions: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Time,
    Duration,
    Proto,
    Source,
    Target,
    Rule,
    LiveSpeed,
    TotalBytes,
    State,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortDirection {
    Asc,
    Desc,
}

static G_LAST_MERGE_MS: AtomicU64 = AtomicU64::new(0);

fn stop_singbox() {
    let _ = std::process::Command::new("sc.exe")
        .args(["stop", "sing-box"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    let _ = std::process::Command::new("taskkill")
        .args(["/f", "/im", "sing-box.exe"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    let _ = std::process::Command::new("route.exe")
        .args(["delete", "0.0.0.0", "mask", "0.0.0.0", "172.19.0.2"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object NextHop -like '172.19.*' | Remove-NetRoute -Confirm:$false; ipconfig /flushdns",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

struct SingboxGuard;

impl Drop for SingboxGuard {
    fn drop(&mut self) {
        stop_singbox();
    }
}

#[repr(C)]
struct SYSTEMTIME {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
}

#[repr(C)]
#[allow(non_snake_case)]
struct TRACKMOUSEEVENT {
    cbSize: u32,
    dwFlags: u32,
    hwndTrack: HWND,
    dwHoverTime: u32,
}

const TME_LEAVE: u32 = 0x00000002;
const WM_MOUSELEAVE: u32 = 0x02A3;

unsafe extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> BOOL>,
        add: BOOL,
    ) -> BOOL;
    fn GetAsyncKeyState(v_key: i32) -> i16;
    fn SetCapture(hwnd: HWND) -> HWND;
    fn ReleaseCapture() -> BOOL;
    fn GetCapture() -> HWND;
    fn SetFocus(hwnd: HWND) -> HWND;
    fn GetLocalTime(lpSystemTime: *mut SYSTEMTIME);
    fn TrackMouseEvent(lpEventTrack: *mut TRACKMOUSEEVENT) -> BOOL;
    fn ScreenToClient(hWnd: HWND, lpPoint: *mut POINT) -> BOOL;
}

fn get_local_time_string() -> String {
    unsafe {
        let mut st = std::mem::zeroed::<SYSTEMTIME>();
        GetLocalTime(&mut st);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
    }
}

fn write_telemetry_log(line: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("O:\\sing-box\\statu\\telemetry.log")
    {
        let _ = writeln!(file, "{}", line);
        let _ = file.flush();
    }
}

fn start_telemetry_logger(app: Arc<Mutex<BarApp>>) {
    std::thread::spawn(move || {
        write_telemetry_log(&format!(
            "[{}] === TELEMETRY LOGGER INITIALIZED (OVERNIGHT AUDIT READY) ===",
            get_local_time_string()
        ));

        let mut minute_count: u64 = 0;
        let mut last_hour_mem: u64 = 0;
        let mut hour_history: Vec<(u64, usize, u64)> = Vec::new();

        loop {
            std::thread::sleep(Duration::from_secs(60));
            minute_count += 1;

            let mut cur_mem = 0u64;
            let mut active_conns = 0usize;
            let mut total_conns = 0usize;
            let mut up_b = 0u64;
            let mut down_b = 0u64;
            let mut tot_up = 0u64;
            let mut tot_down = 0u64;

            if let Ok(s) = app.lock() {
                cur_mem = s.engine_memory;
                active_conns = s.connections.iter().filter(|c| c.is_active).count();
                total_conns = s.connections.len();
                up_b = s.up_bytes;
                down_b = s.down_bytes;
                tot_up = s.total_upload;
                tot_down = s.total_download;
            }

            if cur_mem > 0 {
                hour_history.push((cur_mem, active_conns, tot_up + tot_down));
            }

            if minute_count % 10 == 0 {
                let ts = get_local_time_string();
                write_telemetry_log(&format!(
                    "[{}] [CHECKPOINT] SESSIONS: {} Active / {} Total | MEM: {} ({:.2} MB) | TOTAL: ↑ {} ↓ {} | LIVE: ↑ {} ↓ {}",
                    ts,
                    active_conns,
                    total_conns,
                    cur_mem,
                    cur_mem as f64 / (1024.0 * 1024.0),
                    format_bytes(tot_up),
                    format_bytes(tot_down),
                    format_speed(up_b),
                    format_speed(down_b),
                ));
            }

            if minute_count >= 60 {
                minute_count = 0;
                let ts = get_local_time_string();

                let mut min_m = cur_mem;
                let mut max_m = cur_mem;
                for (m, _, _) in &hour_history {
                    if *m < min_m { min_m = *m; }
                    if *m > max_m { max_m = *m; }
                }

                let delta_str = if last_hour_mem > 0 {
                    let diff = cur_mem as i64 - last_hour_mem as i64;
                    let diff_mb = diff as f64 / (1024.0 * 1024.0);
                    if diff >= 0 {
                        format!("+{} B (+{:.2} MB)", diff, diff_mb)
                    } else {
                        format!("-{} B ({:.2} MB)", diff.abs(), diff_mb)
                    }
                } else {
                    "BASELINE".to_string()
                };

                let health_diag = if last_hour_mem > 0 && cur_mem > last_hour_mem + (20 * 1024 * 1024) {
                    "⚠️ [POSSIBLE LEAK WARNING] Monotonic Growth Exceeds 20MB/hr"
                } else {
                    "✅ [HEALTHY] Memory Oscillating Within Stable Normal Range"
                };

                write_telemetry_log(&format!(
                    "[{}] =================== HOURLY HEALTH AUDIT ===================",
                    ts
                ));
                write_telemetry_log(&format!(
                    "[{}] SESSIONS : {} Active / {} Total Tracked",
                    ts, active_conns, total_conns
                ));
                write_telemetry_log(&format!(
                    "[{}] MEMORY   : Current: {:.2} MB | Min: {:.2} MB | Max: {:.2} MB | Δ 1hr: {}",
                    ts,
                    cur_mem as f64 / (1024.0 * 1024.0),
                    min_m as f64 / (1024.0 * 1024.0),
                    max_m as f64 / (1024.0 * 1024.0),
                    delta_str
                ));
                write_telemetry_log(&format!(
                    "[{}] BANDWIDTH: Session Total ↑ {} | ↓ {}",
                    ts,
                    format_bytes(tot_up),
                    format_bytes(tot_down)
                ));
                write_telemetry_log(&format!(
                    "[{}] DIAGNOSIS: {}",
                    ts, health_diag
                ));
                write_telemetry_log(&format!(
                    "[{}] ===========================================================",
                    ts
                ));

                last_hour_mem = cur_mem;
                hour_history.clear();
            }
        }
    });
}

unsafe extern "system" fn console_ctrl_handler(_ctrl_type: u32) -> BOOL {
    stop_singbox();
    BOOL(0)
}

fn parse_time(start_str: &str) -> String {
    if let Some(t_idx) = start_str.find('T') {
        let rest = &start_str[t_idx + 1..];
        if rest.len() >= 8 {
            return rest[..8].to_string();
        }
    }
    if start_str.is_empty() {
        "-".to_string()
    } else {
        start_str.to_string()
    }
}

fn parse_rfc3339_epoch(s: &str) -> Option<u64> {
    let (date_str, rest) = s.split_once('T')?;
    let mut d_iter = date_str.split('-');
    let y: u64 = d_iter.next()?.parse().ok()?;
    let m: u64 = d_iter.next()?.parse().ok()?;
    let d: u64 = d_iter.next()?.parse().ok()?;

    let (time_str, tz_str, is_minus) = if let Some((t, tz)) = rest.split_once('+') {
        (t, tz, false)
    } else if let Some(idx) = rest.rfind('-') {
        (&rest[..idx], &rest[idx + 1..], true)
    } else if let Some(t) = rest.strip_suffix('Z') {
        (t, "00:00", false)
    } else {
        (rest, "00:00", false)
    };

    let time_clean = time_str.split('.').next()?;
    let mut t_iter = time_clean.split(':');
    let hour: u64 = t_iter.next()?.parse().ok()?;
    let min: u64 = t_iter.next()?.parse().ok()?;
    let sec: u64 = t_iter.next()?.parse().ok()?;

    let (tz_hour, tz_min) = if let Some((h, m)) = tz_str.split_once(':') {
        (h.parse::<u64>().unwrap_or(0), m.parse::<u64>().unwrap_or(0))
    } else {
        (0, 0)
    };
    let tz_offset_secs = tz_hour * 3600 + tz_min * 60;

    let month_days = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let leap_years = (y.saturating_sub(1969)) / 4;
    let days = (y.saturating_sub(1970)) * 365 + leap_years
        + month_days[(m.max(1).min(12) - 1) as usize] + d.saturating_sub(1);
    let mut utc_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    if is_minus {
        utc_secs += tz_offset_secs;
    } else {
        utc_secs = utc_secs.saturating_sub(tz_offset_secs);
    }
    Some(utc_secs)
}

fn format_duration(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

fn format_proto(network: &str, inbound: &str) -> String {
    let net = if network.is_empty() { "TCP" } else { network }.to_ascii_uppercase();
    let inb = if inbound.contains("tun") {
        "TUN"
    } else if inbound.contains("10804") {
        "MIX"
    } else if inbound.contains("7890") {
        "7890"
    } else {
        "IN"
    };
    format!("{}/{}", net, inb)
}

fn format_rule(rule: &str, chain: &str) -> String {
    let clean_rule = if rule.contains("geosite") || rule.contains("geoip") {
        "geosite-cn"
    } else if rule.contains("ip_is_private") {
        "private"
    } else if rule == "final" {
        "final"
    } else if let Some((r, _)) = rule.split_once("=>") {
        r.trim()
    } else if rule.is_empty() {
        "default"
    } else {
        rule
    };
    format!("{} [{}]", chain, clean_rule)
}

fn merge_connections(existing: &mut Vec<ConnectionItem>, new_items: Vec<ConnectionItem>) {
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let prev_ms = G_LAST_MERGE_MS.swap(now_ms, Ordering::Relaxed);
    let dt_secs = if prev_ms > 0 && now_ms > prev_ms {
        (now_ms - prev_ms) as f64 / 1000.0
    } else {
        0.0
    };

    let mut new_map: std::collections::HashMap<String, ConnectionItem> = new_items
        .into_iter()
        .map(|item| (item.id.clone(), item))
        .collect();

    for conn in existing.iter_mut() {
        if let Some(mut updated) = new_map.remove(&conn.id) {
            let d_up = updated.upload.saturating_sub(conn.prev_upload);
            let d_down = updated.download.saturating_sub(conn.prev_download);
            conn.prev_upload = updated.upload;
            conn.prev_download = updated.download;
            conn.upload = updated.upload;
            conn.download = updated.download;
            conn.chains = std::mem::take(&mut updated.chains);
            conn.rule = std::mem::take(&mut updated.rule);
            conn.is_active = true;
            if conn.start_epoch > 0 && now_epoch >= conn.start_epoch {
                conn.duration_secs = now_epoch - conn.start_epoch;
            }
            if dt_secs > 0.0 {
                conn.cur_up_speed = (d_up as f64 / dt_secs) as u64;
                conn.cur_down_speed = (d_down as f64 / dt_secs) as u64;
            } else {
                conn.cur_up_speed = 0;
                conn.cur_down_speed = 0;
            }
            conn.avg_speed = (conn.upload + conn.download) / conn.duration_secs.max(1);
            conn.dl_ul_ratio = if conn.upload > 0 {
                conn.download as f32 / conn.upload as f32
            } else {
                0.0
            };
            conn.is_idle = conn.cur_up_speed == 0 && conn.cur_down_speed == 0;
        } else {
            conn.is_active = false;
            conn.cur_up_speed = 0;
            conn.cur_down_speed = 0;
            conn.is_idle = false;
        }
    }

    for (_, mut item) in new_map {
        item.is_active = true;
        item.prev_upload = item.upload;
        item.prev_download = item.download;
        item.start_epoch = parse_rfc3339_epoch(&item.start).unwrap_or(now_epoch);
        if item.start_epoch > 0 && now_epoch >= item.start_epoch {
            item.duration_secs = now_epoch - item.start_epoch;
        }
        item.cur_up_speed = 0;
        item.cur_down_speed = 0;
        item.avg_speed = (item.upload + item.download) / item.duration_secs.max(1);
        item.dl_ul_ratio = if item.upload > 0 {
            item.download as f32 / item.upload as f32
        } else {
            0.0
        };
        item.is_idle = true;
        existing.push(item);
    }

    existing.sort_by(|a, b| {
        b.is_active
            .cmp(&a.is_active)
            .then_with(|| (b.upload + b.download).cmp(&(a.upload + a.download)))
    });

    if existing.len() > 1000 {
        existing.truncate(1000);
    }
}

struct BarApp {
    up_bytes: u64,
    down_bytes: u64,
    connected: bool,
    popup_visible: bool,
    connections: Vec<ConnectionItem>,
    scroll_offset: usize,
    total_upload: u64,
    total_download: u64,
    engine_memory: u64,
    sort_col: SortColumn,
    sort_dir: SortDirection,
    search_query: String,
    search_active: bool,
    menu_open: bool,
    menu_anim: f32,
    hover_btn: Option<usize>,
    active_sub_name: String,
}

static G_APP: OnceLock<Arc<Mutex<BarApp>>> = OnceLock::new();
static G_BAR_HWND: AtomicIsize = AtomicIsize::new(0);
static G_POPUP_HWND: AtomicIsize = AtomicIsize::new(0);

fn get_bar_hwnd() -> HWND {
    HWND(G_BAR_HWND.load(Ordering::Relaxed) as *mut _)
}

fn get_popup_hwnd() -> HWND {
    HWND(G_POPUP_HWND.load(Ordering::Relaxed) as *mut _)
}

fn format_speed(bytes_per_sec: u64) -> String {
    let val = bytes_per_sec as f64;
    if val >= 1024.0 * 1024.0 {
        format!("{:.2} MB/s", val / (1024.0 * 1024.0))
    } else if val >= 1024.0 {
        format!("{:.1} KB/s", val / 1024.0)
    } else {
        format!("{} B/s", bytes_per_sec)
    }
}

fn format_bytes(bytes: u64) -> String {
    let val = bytes as f64;
    if val >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1}G", val / (1024.0 * 1024.0 * 1024.0))
    } else if val >= 1024.0 * 1024.0 {
        format!("{:.1}M", val / (1024.0 * 1024.0))
    } else if val >= 1024.0 {
        format!("{:.0}K", val / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

const MENU_BTN_COUNT: usize = 5;
const MENU_BTN_WIDTHS: [i32; 5] = [68, 96, 78, 72, 62];
const MENU_BTN_GAP: i32 = 6;
const MENU_BTN_START: i32 = 6;
const MENU_TOTAL_W: i32 = 68 + 96 + 78 + 72 + 62 + MENU_BTN_GAP * 5;

fn menu_button_offset(idx: usize) -> i32 {
    let limit = idx.min(MENU_BTN_COUNT);
    let mut x = 0;
    for i in 0..limit {
        x += MENU_BTN_WIDTHS[i] + MENU_BTN_GAP;
    }
    x
}

fn menu_button_label(idx: usize, connected: bool, sub: &str) -> String {
    match idx {
        0 => {
            if connected {
                "⏹ 停止".to_string()
            } else {
                "▶ 启动".to_string()
            }
        }
        1 => format!("🌐 {}", sub),
        2 => "📊 观测台".to_string(),
        3 => "📝 日志".to_string(),
        _ => "✕ 退出".to_string(),
    }
}

fn menu_button_color(idx: usize, connected: bool) -> u32 {
    match idx {
        0 => {
            if connected {
                rgb(248, 113, 113)
            } else {
                rgb(52, 211, 153)
            }
        }
        1 => rgb(167, 139, 250),
        2 => rgb(56, 189, 248),
        3 => rgb(251, 191, 36),
        _ => rgb(203, 213, 225),
    }
}

fn menu_button_at(x: i32, base_w: i32, anim: f32) -> Option<usize> {
    if anim <= 0.01 {
        return None;
    }
    for idx in 0..MENU_BTN_COUNT {
        let start_p = idx as f32 * 0.12;
        let p = ((anim - start_p) / 0.40).clamp(0.0, 1.0);
        if p <= 0.0 {
            continue;
        }
        let slide_x = ((1.0 - p) * 35.0) as i32;
        let left = base_w + MENU_BTN_START + menu_button_offset(idx) + slide_x;
        let right = left + MENU_BTN_WIDTHS[idx];
        if x >= left && x < right {
            return Some(idx);
        }
    }
    None
}

fn active_subscription_name() -> String {
    if let Ok(data) = std::fs::read_to_string("O:\\sing-box\\subscriptions.json") {
        if let Ok(cfg) = serde_json::from_str::<SubscriptionsConfig>(&data) {
            if !cfg.active.is_empty() {
                return cfg.active;
            }
        }
    }
    "main".to_string()
}

fn cycle_subscription() -> Option<String> {
    let data = std::fs::read_to_string("O:\\sing-box\\subscriptions.json").ok()?;
    let cfg: SubscriptionsConfig = serde_json::from_str(&data).ok()?;
    if cfg.subscriptions.is_empty() {
        return None;
    }
    let names: Vec<String> = cfg.subscriptions.keys().cloned().collect();
    let cur_idx = names.iter().position(|n| n == &cfg.active).unwrap_or(0);
    let next = names[(cur_idx + 1) % names.len()].clone();
    let target = next.clone();
    std::thread::spawn(move || {
        let _ = std::process::Command::new("python")
            .args(["O:\\sing-box\\update_sub.py", &target])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    });
    Some(next)
}

fn set_menu_open(open: bool) {
    if let Some(app) = G_APP.get() {
        if let Ok(mut s) = app.lock() {
            s.menu_open = open;
            if !open {
                s.hover_btn = None;
            }
        }
    }
    let hwnd = get_bar_hwnd();
    if !hwnd.0.is_null() {
        unsafe {
            let _ = SetTimer(hwnd, 2, 16, None);
        }
    }
}

unsafe fn measure_base_width(hwnd: HWND, active_count: usize, up_bytes: u64, down_bytes: u64) -> i32 {
    let hdc = GetDC(hwnd);
    if hdc.0.is_null() {
        return 200;
    }
    let font = create_font(13, 600);
    let old_font = SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    let count_text = active_count.to_string();
    let up_text = format!("↑ {}", format_speed(up_bytes));
    let down_text = format!("↓ {}", format_speed(down_bytes));
    let mut count_u16: Vec<u16> = count_text.encode_utf16().collect();
    let mut up_u16: Vec<u16> = up_text.encode_utf16().collect();
    let mut down_u16: Vec<u16> = down_text.encode_utf16().collect();
    let mut count_size = SIZE::default();
    let mut up_size = SIZE::default();
    let mut down_size = SIZE::default();
    let _ = GetTextExtentPoint32W(hdc, &count_u16, &mut count_size);
    let _ = GetTextExtentPoint32W(hdc, &up_u16, &mut up_size);
    let _ = GetTextExtentPoint32W(hdc, &down_u16, &mut down_size);
    SelectObject(hdc, old_font);
    let _ = DeleteObject(font);
    let _ = ReleaseDC(hwnd, hdc);
    (22 + count_size.cx + 10 + up_size.cx + 12 + down_size.cx + 14).max(200)
}

const COLUMN_LEFT: [i32; 9] = [14, 94, 159, 244, 374, 654, 854, 984, 1124];
const COLUMN_RIGHT: [i32; 9] = [94, 159, 244, 374, 654, 854, 984, 1124, 1164];

fn column_left(idx: usize, _width: i32) -> i32 {
    COLUMN_LEFT[idx.min(8)]
}

fn column_right(idx: usize, width: i32) -> i32 {
    if idx >= 8 {
        width - 16
    } else {
        COLUMN_RIGHT[idx]
    }
}

fn column_at(x: i32, width: i32) -> Option<usize> {
    for idx in 0..9 {
        if x >= column_left(idx, width) && x < column_right(idx, width) {
            return Some(idx);
        }
    }
    None
}

fn column_index(col: SortColumn) -> usize {
    match col {
        SortColumn::Time => 0,
        SortColumn::Duration => 1,
        SortColumn::Proto => 2,
        SortColumn::Source => 3,
        SortColumn::Target => 4,
        SortColumn::Rule => 5,
        SortColumn::LiveSpeed => 6,
        SortColumn::TotalBytes => 7,
        SortColumn::State => 8,
    }
}

fn index_column(idx: usize) -> SortColumn {
    match idx {
        0 => SortColumn::Time,
        1 => SortColumn::Duration,
        2 => SortColumn::Proto,
        3 => SortColumn::Source,
        4 => SortColumn::Target,
        5 => SortColumn::Rule,
        6 => SortColumn::LiveSpeed,
        7 => SortColumn::TotalBytes,
        _ => SortColumn::State,
    }
}

fn connection_matches(conn: &ConnectionItem, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let q = query.to_lowercase();
    let fields: [&String; 8] = [
        &conn.metadata.host,
        &conn.metadata.destination_ip,
        &conn.metadata.source_ip,
        &conn.metadata.destination_port,
        &conn.metadata.source_port,
        &conn.metadata.network,
        &conn.metadata.inbound_type,
        &conn.rule,
    ];
    if fields.iter().any(|f| f.to_lowercase().contains(&q)) {
        return true;
    }
    conn.chains.iter().any(|c| c.to_lowercase().contains(&q))
}

fn sort_connections(list: &mut Vec<ConnectionItem>, col: SortColumn, dir: SortDirection) {
    list.sort_by(|a, b| {
        let ord = match col {
            SortColumn::Time => a.start_epoch.cmp(&b.start_epoch),
            SortColumn::Duration => a.duration_secs.cmp(&b.duration_secs),
            SortColumn::Proto => {
                format_proto(&a.metadata.network, &a.metadata.inbound_type)
                    .cmp(&format_proto(&b.metadata.network, &b.metadata.inbound_type))
            }
            SortColumn::Source => a
                .metadata
                .source_ip
                .cmp(&b.metadata.source_ip)
                .then_with(|| a.metadata.source_port.cmp(&b.metadata.source_port)),
            SortColumn::Target => a
                .metadata
                .host
                .cmp(&b.metadata.host)
                .then_with(|| a.metadata.destination_ip.cmp(&b.metadata.destination_ip)),
            SortColumn::Rule => a.rule.cmp(&b.rule),
            SortColumn::LiveSpeed => {
                (a.cur_up_speed + a.cur_down_speed).cmp(&(b.cur_up_speed + b.cur_down_speed))
            }
            SortColumn::TotalBytes => (a.upload + a.download).cmp(&(b.upload + b.download)),
            SortColumn::State => {
                let rank = |c: &ConnectionItem| {
                    if c.is_active && !c.is_idle {
                        0u8
                    } else if c.is_active {
                        1u8
                    } else {
                        2u8
                    }
                };
                rank(a).cmp(&rank(b))
            }
        };
        match dir {
            SortDirection::Asc => ord,
            SortDirection::Desc => ord.reverse(),
        }
    });
}

unsafe fn fill_round(
    hdc: HDC,
    l: i32,
    t: i32,
    r: i32,
    b: i32,
    radius: i32,
    fill: u32,
    border: u32,
) {
    let brush = CreateSolidBrush(COLORREF(fill));
    let pen = CreatePen(PS_SOLID, 1, COLORREF(border));
    let old_brush = SelectObject(hdc, brush);
    let old_pen = SelectObject(hdc, pen);
    let _ = RoundRect(hdc, l, t, r, b, radius, radius);
    SelectObject(hdc, old_pen);
    SelectObject(hdc, old_brush);
    let _ = DeleteObject(pen);
    let _ = DeleteObject(brush);
}

unsafe fn fill_area(hdc: HDC, l: i32, t: i32, r: i32, b: i32, color: u32) {
    let brush = CreateSolidBrush(COLORREF(color));
    let rect = RECT {
        left: l,
        top: t,
        right: r,
        bottom: b,
    };
    let _ = FillRect(hdc, &rect, brush);
    let _ = DeleteObject(brush);
}

unsafe fn draw_str(
    hdc: HDC,
    text: &str,
    l: i32,
    t: i32,
    r: i32,
    b: i32,
    color: u32,
    fmt: DRAW_TEXT_FORMAT,
) {
    let mut buf: Vec<u16> = text.encode_utf16().collect();
    let mut rect = RECT {
        left: l,
        top: t,
        right: r,
        bottom: b,
    };
    SetTextColor(hdc, COLORREF(color));
    let _ = DrawTextW(hdc, &mut buf, &mut rect, fmt);
}

fn ensure_singbox_running() {
    if TcpStream::connect("127.0.0.1:9090").is_ok() {
        return;
    }

    let _ = std::process::Command::new("sc.exe")
        .args(["start", "sing-box"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    for _ in 0..6 {
        std::thread::sleep(Duration::from_millis(250));
        if TcpStream::connect("127.0.0.1:9090").is_ok() {
            return;
        }
    }

    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "Start-Process -FilePath 'O:\\sing-box\\sing-box.exe' -ArgumentList 'run -D O:\\sing-box -c O:\\sing-box\\config.json' -Verb RunAs -WindowStyle Hidden",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

fn fetch_connections() -> Option<ConnectionsResponse> {
    let mut stream = TcpStream::connect("127.0.0.1:9090").ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(600))).ok()?;
    stream
        .write_all(b"GET /connections HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = Vec::with_capacity(32768);
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response.ends_with(b"0\r\n\r\n") || response.windows(5).any(|w| w == b"\r\n0\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&response);
    let body_start = text.find("\r\n\r\n")? + 4;
    let body = &text[body_start..];
    let mut clean_body = String::new();
    if text.contains("Transfer-Encoding: chunked") || text.contains("transfer-encoding: chunked") {
        let mut rest = body;
        while let Some(pos) = rest.find("\r\n") {
            let hex_str = rest[..pos].trim();
            if let Ok(chunk_len) = usize::from_str_radix(hex_str, 16) {
                if chunk_len == 0 {
                    break;
                }
                let data_start = pos + 2;
                if data_start + chunk_len <= rest.len() {
                    clean_body.push_str(&rest[data_start..data_start + chunk_len]);
                    rest = &rest[data_start + chunk_len..];
                    if rest.starts_with("\r\n") {
                        rest = &rest[2..];
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    } else {
        clean_body = body.to_string();
    }
    let resp: ConnectionsResponse = serde_json::from_str(&clean_body).ok()?;
    Some(resp)
}

fn stream_traffic(app: Arc<Mutex<BarApp>>) {
    loop {
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:9090") {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
            if stream
                .write_all(b"GET /traffic HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n\r\n")
                .is_ok()
            {
                let reader = BufReader::new(stream);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        let trimmed = l.trim();
                        if trimmed.starts_with('{') && trimmed.ends_with('}') {
                            if let Ok(traffic) = serde_json::from_str::<TrafficMessage>(trimmed) {
                                if let Ok(mut s) = app.lock() {
                                    s.up_bytes = traffic.up;
                                    s.down_bytes = traffic.down;
                                    s.connected = true;
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        if let Ok(mut s) = app.lock() {
            s.connected = false;
            s.up_bytes = 0;
            s.down_bytes = 0;
        }
        std::thread::sleep(Duration::from_millis(1500));
    }
}

fn poll_connections_bg(app: Arc<Mutex<BarApp>>) {
    loop {
        if let Some(resp) = fetch_connections() {
            let mut is_popup_open = false;
            if let Ok(mut s) = app.lock() {
                s.total_upload = resp.upload_total;
                s.total_download = resp.download_total;
                s.engine_memory = resp.memory;
                merge_connections(&mut s.connections, resp.connections);
                is_popup_open = s.popup_visible;
            }
            if is_popup_open {
                let phwnd = get_popup_hwnd();
                if !phwnd.0.is_null() {
                    unsafe {
                        let _ = InvalidateRect(phwnd, None, FALSE);
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
}

unsafe fn create_font(size: i32, weight: i32) -> HFONT {
    CreateFontW(
        size,
        0,
        0,
        0,
        weight,
        0,
        0,
        0,
        DEFAULT_CHARSET.0 as u32,
        OUT_DEFAULT_PRECIS.0 as u32,
        CLIP_DEFAULT_PRECIS.0 as u32,
        5,
        DEFAULT_PITCH.0 as u32,
        w!("Segoe UI"),
    )
}

unsafe fn toggle_popup() {
    let bar_hwnd = get_bar_hwnd();
    let popup_hwnd = get_popup_hwnd();
    if bar_hwnd.0.is_null() || popup_hwnd.0.is_null() {
        return;
    }
    let mut is_open = false;
    if let Some(app) = G_APP.get() {
        if let Ok(mut s) = app.lock() {
            s.popup_visible = !s.popup_visible;
            is_open = s.popup_visible;
            if is_open {
                s.scroll_offset = 0;
            }
        }
    }
    if is_open {
        let mut bar_rect = RECT::default();
        let _ = GetWindowRect(bar_hwnd, &mut bar_rect);
        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);
        let popup_w = 1180;
        let popup_h = 660;
        let mut x = bar_rect.left;
        let mut y = bar_rect.bottom + 4;
        if x < 10 {
            x = 10;
        }
        if x + popup_w > screen_w - 10 {
            x = screen_w - popup_w - 10;
        }
        if y + popup_h > screen_h - 10 {
            y = (screen_h - popup_h - 10).max(10);
        }
        let _ = SetWindowPos(
            popup_hwnd,
            HWND_TOPMOST,
            x,
            y,
            popup_w,
            popup_h,
            SWP_SHOWWINDOW,
        );
        let _ = InvalidateRect(popup_hwnd, None, FALSE);

        if let Some(app) = G_APP.get() {
            let bg_app = app.clone();
            std::thread::spawn(move || {
                if let Some(resp) = fetch_connections() {
                    if let Ok(mut s) = bg_app.lock() {
                        s.total_upload = resp.upload_total;
                        s.total_download = resp.download_total;
                        s.engine_memory = resp.memory;
                        merge_connections(&mut s.connections, resp.connections);
                    }
                    let phwnd = get_popup_hwnd();
                    if !phwnd.0.is_null() {
                        unsafe {
                            let _ = InvalidateRect(phwnd, None, FALSE);
                        }
                    }
                }
            });
        }
    } else {
        let _ = ShowWindow(popup_hwnd, SW_HIDE);
    }
}

unsafe extern "system" fn wndproc_bar(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => LRESULT(1),
        WM_NCHITTEST => {
            let r_down = (GetAsyncKeyState(0x02) as u16 & 0x8000) != 0;
            if r_down || GetCapture() == hwnd {
                return LRESULT(1);
            }
            let mut pt = POINT {
                x: (lparam.0 & 0xffff) as i16 as i32,
                y: ((lparam.0 >> 16) & 0xffff) as i16 as i32,
            };
            let _ = ScreenToClient(hwnd, &mut pt);
            let mut anim = 0.0f32;
            let mut base_w = 200;
            if let Some(app) = G_APP.get() {
                if let Ok(s) = app.lock() {
                    anim = s.menu_anim;
                    base_w = measure_base_width(
                        hwnd,
                        s.connections.iter().filter(|c| c.is_active).count(),
                        s.up_bytes,
                        s.down_bytes,
                    );
                }
            }
            if anim > 0.1 && pt.x > base_w {
                LRESULT(1)
            } else {
                LRESULT(-1)
            }
        }
        WM_RBUTTONDOWN => {
            SetCapture(hwnd);
            LRESULT(0)
        }
        WM_RBUTTONUP => {
            if GetCapture() == hwnd {
                let _ = ReleaseCapture();
            }
            let mut next_open = false;
            if let Some(app) = G_APP.get() {
                if let Ok(s) = app.lock() {
                    next_open = !s.menu_open;
                }
            }
            set_menu_open(next_open);
            LRESULT(0)
        }
        WM_MOUSEMOVE => {
            let x = (lparam.0 & 0xffff) as i16 as i32;
            let mut changed = false;
            if let Some(app) = G_APP.get() {
                if let Ok(mut s) = app.lock() {
                    let base_w = measure_base_width(
                        hwnd,
                        s.connections.iter().filter(|c| c.is_active).count(),
                        s.up_bytes,
                        s.down_bytes,
                    );
                    let anim = s.menu_anim;
                    let new_hover = if x > base_w {
                        menu_button_at(x, base_w, anim)
                    } else {
                        None
                    };
                    if new_hover != s.hover_btn {
                        s.hover_btn = new_hover;
                        changed = true;
                    }
                }
            }
            let mut tme = TRACKMOUSEEVENT {
                cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                dwFlags: TME_LEAVE,
                hwndTrack: hwnd,
                dwHoverTime: 0,
            };
            let _ = TrackMouseEvent(&mut tme);
            if changed {
                let _ = InvalidateRect(hwnd, None, FALSE);
            }
            LRESULT(0)
        }
        WM_MOUSELEAVE => {
            let mut changed = false;
            if let Some(app) = G_APP.get() {
                if let Ok(mut s) = app.lock() {
                    if s.hover_btn.is_some() {
                        s.hover_btn = None;
                        changed = true;
                    }
                }
            }
            if changed {
                let _ = InvalidateRect(hwnd, None, FALSE);
            }
            LRESULT(0)
        }
        WM_LBUTTONDOWN => {
            let x = (lparam.0 & 0xffff) as i16 as i32;
            let mut action: Option<usize> = None;
            let mut connected = false;
            if let Some(app) = G_APP.get() {
                if let Ok(s) = app.lock() {
                    connected = s.connected;
                    let base_w = measure_base_width(
                        hwnd,
                        s.connections.iter().filter(|c| c.is_active).count(),
                        s.up_bytes,
                        s.down_bytes,
                    );
                    if x > base_w {
                        action = menu_button_at(x, base_w, s.menu_anim);
                    }
                }
            }
            if let Some(idx) = action {
                match idx {
                    0 => {
                        if connected {
                            stop_singbox();
                            if let Some(app) = G_APP.get() {
                                if let Ok(mut s) = app.lock() {
                                    s.connected = false;
                                    s.up_bytes = 0;
                                    s.down_bytes = 0;
                                }
                            }
                            let _ = InvalidateRect(hwnd, None, FALSE);
                        } else {
                            std::thread::spawn(|| {
                                ensure_singbox_running();
                            });
                        }
                    }
                    1 => {
                        if let Some(next) = cycle_subscription() {
                            if let Some(app) = G_APP.get() {
                                if let Ok(mut s) = app.lock() {
                                    s.active_sub_name = next;
                                }
                            }
                            let _ = InvalidateRect(hwnd, None, FALSE);
                        }
                    }
                    2 => {
                        toggle_popup();
                    }
                    3 => {
                        std::thread::spawn(|| {
                            let _ = std::process::Command::new("notepad.exe")
                                .arg("O:\\sing-box\\statu\\telemetry.log")
                                .creation_flags(CREATE_NO_WINDOW)
                                .spawn();
                        });
                    }
                    _ => {
                        stop_singbox();
                        let _ = PostQuitMessage(0);
                    }
                }
                set_menu_open(false);
            }
            LRESULT(0)
        }
        WM_TIMER => {
            if wparam.0 == 1 {
                let _ = InvalidateRect(hwnd, None, FALSE);
            } else if wparam.0 == 2 {
                let mut finished = false;
                if let Some(app) = G_APP.get() {
                    if let Ok(mut s) = app.lock() {
                        if s.menu_open && s.menu_anim < 1.0 {
                            s.menu_anim = (s.menu_anim + 0.10).min(1.0);
                        } else if !s.menu_open && s.menu_anim > 0.0 {
                            s.menu_anim = (s.menu_anim - 0.12).max(0.0);
                        }
                        finished = (s.menu_open && s.menu_anim >= 1.0)
                            || (!s.menu_open && s.menu_anim <= 0.0);
                    }
                }
                let _ = InvalidateRect(hwnd, None, FALSE);
                if finished {
                    let _ = KillTimer(hwnd, 2);
                }
            }
            LRESULT(0)
        }
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);
            let mut rect = RECT::default();
            let _ = GetClientRect(hwnd, &mut rect);
            let width = rect.right;
            let height = rect.bottom;

            let mem_dc = CreateCompatibleDC(hdc);
            let mem_bm = CreateCompatibleBitmap(hdc, width, height);
            let old_bm = SelectObject(mem_dc, mem_bm);

            let bg_brush = CreateSolidBrush(COLORREF(rgb(13, 16, 22)));
            let border_pen = CreatePen(PS_SOLID, 1, COLORREF(rgb(35, 45, 60)));
            let old_brush = SelectObject(mem_dc, bg_brush);
            let old_pen = SelectObject(mem_dc, border_pen);
            let _ = RoundRect(mem_dc, 0, 0, width, height, 6, 6);
            SelectObject(mem_dc, old_pen);
            SelectObject(mem_dc, old_brush);
            let _ = DeleteObject(border_pen);
            let _ = DeleteObject(bg_brush);

            let mut connected = false;
            let mut up_bytes = 0;
            let mut down_bytes = 0;
            let mut active_count = 0usize;
            let mut menu_anim = 0.0f32;
            let mut hover_btn: Option<usize> = None;
            let mut active_sub = String::new();
            if let Some(app) = G_APP.get() {
                if let Ok(s) = app.lock() {
                    connected = s.connected;
                    up_bytes = s.up_bytes;
                    down_bytes = s.down_bytes;
                    active_count = s.connections.iter().filter(|c| c.is_active).count();
                    menu_anim = s.menu_anim;
                    hover_btn = s.hover_btn;
                    active_sub = s.active_sub_name.clone();
                }
            }

            let dot_color = if connected {
                COLORREF(rgb(16, 185, 129))
            } else {
                COLORREF(rgb(239, 68, 68))
            };
            let dot_brush = CreateSolidBrush(dot_color);
            let dot_pen = CreatePen(PS_SOLID, 1, dot_color);
            let old_db = SelectObject(mem_dc, dot_brush);
            let old_dp = SelectObject(mem_dc, dot_pen);
            let dot_y = height / 2 - 3;
            let _ = RoundRect(mem_dc, 9, dot_y, 16, dot_y + 7, 7, 7);
            SelectObject(mem_dc, old_dp);
            SelectObject(mem_dc, old_db);
            let _ = DeleteObject(dot_pen);
            let _ = DeleteObject(dot_brush);

            let font = create_font(13, 600);
            let old_font = SelectObject(mem_dc, font);
            SetBkMode(mem_dc, TRANSPARENT);

            let count_text = format!("{}", active_count);
            let up_text = format!("↑ {}", format_speed(up_bytes));
            let down_text = format!("↓ {}", format_speed(down_bytes));
            let mut count_u16: Vec<u16> = count_text.encode_utf16().collect();
            let mut up_u16: Vec<u16> = up_text.encode_utf16().collect();
            let mut down_u16: Vec<u16> = down_text.encode_utf16().collect();

            let mut count_size = SIZE::default();
            let mut up_size = SIZE::default();
            let mut down_size = SIZE::default();
            let _ = GetTextExtentPoint32W(mem_dc, &count_u16, &mut count_size);
            let _ = GetTextExtentPoint32W(mem_dc, &up_u16, &mut up_size);
            let _ = GetTextExtentPoint32W(mem_dc, &down_u16, &mut down_size);

            let mut count_rect = RECT {
                left: 22,
                top: 0,
                right: 22 + count_size.cx,
                bottom: height,
            };
            SetTextColor(mem_dc, COLORREF(rgb(148, 163, 184)));
            let _ = DrawTextW(
                mem_dc,
                &mut count_u16,
                &mut count_rect,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );

            let up_left = 22 + count_size.cx + 10;
            let mut up_rect = RECT {
                left: up_left,
                top: 0,
                right: up_left + up_size.cx,
                bottom: height,
            };
            SetTextColor(mem_dc, COLORREF(rgb(0, 210, 255)));
            let _ = DrawTextW(
                mem_dc,
                &mut up_u16,
                &mut up_rect,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );

            let down_left = up_left + up_size.cx + 12;
            let mut down_rect = RECT {
                left: down_left,
                top: 0,
                right: down_left + down_size.cx,
                bottom: height,
            };
            SetTextColor(mem_dc, COLORREF(rgb(16, 240, 160)));
            let _ = DrawTextW(
                mem_dc,
                &mut down_u16,
                &mut down_rect,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );

            let base_w = (down_left + down_size.cx + 14).max(200);

            if menu_anim > 0.01 {
                let sep_pen = CreatePen(PS_SOLID, 1, COLORREF(rgb(45, 55, 75)));
                let old_sep_pen = SelectObject(mem_dc, sep_pen);
                let _ = MoveToEx(mem_dc, base_w + 2, 5, None);
                let _ = LineTo(mem_dc, base_w + 2, height - 5);
                SelectObject(mem_dc, old_sep_pen);
                let _ = DeleteObject(sep_pen);

                let btn_origin = base_w + MENU_BTN_START;
                let btn_font = create_font(13, 600);
                let old_btn_font = SelectObject(mem_dc, btn_font);
                for idx in 0..MENU_BTN_COUNT {
                    let start_p = idx as f32 * 0.12;
                    let p = ((menu_anim - start_p) / 0.40).clamp(0.0, 1.0);
                    if p <= 0.0 {
                        continue;
                    }
                    let slide_x = ((1.0 - p) * 35.0) as i32;
                    let left = btn_origin + menu_button_offset(idx) + slide_x;
                    let right = left + MENU_BTN_WIDTHS[idx];
                    let top = 3;
                    let bottom = height - 3;
                    if hover_btn == Some(idx) {
                        fill_round(
                            mem_dc,
                            left,
                            top,
                            right,
                            bottom,
                            6,
                            rgb(28, 38, 54),
                            rgb(55, 70, 95),
                        );
                    }
                    let label = menu_button_label(idx, connected, &active_sub);
                    let color = menu_button_color(idx, connected);
                    draw_str(
                        mem_dc,
                        &label,
                        left,
                        top,
                        right,
                        bottom,
                        color,
                        DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
                    );
                }
                SelectObject(mem_dc, old_btn_font);
                let _ = DeleteObject(btn_font);
            }

            let cur_w = base_w + ((MENU_TOTAL_W as f32) * menu_anim) as i32;
            if cur_w != width {
                let mut cur_rect = RECT::default();
                let _ = GetWindowRect(hwnd, &mut cur_rect);
                let _ = SetWindowPos(
                    hwnd,
                    HWND_TOPMOST,
                    cur_rect.left,
                    cur_rect.top,
                    cur_w,
                    height,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }

            let _ = BitBlt(hdc, 0, 0, width, height, mem_dc, 0, 0, SRCCOPY);
            SelectObject(mem_dc, old_font);
            let _ = DeleteObject(font);
            SelectObject(mem_dc, old_bm);
            let _ = DeleteObject(mem_bm);
            let _ = DeleteDC(mem_dc);
            let _ = EndPaint(hwnd, &ps);
            LRESULT(0)
        }
        WM_DESTROY => {
            stop_singbox();
            let _ = PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcA(hwnd, msg, wparam, lparam),
    }
}

unsafe extern "system" fn wndproc_popup(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => LRESULT(1),
        WM_MOUSEWHEEL => {
            let delta = ((wparam.0 >> 16) as i16) as i32;
            let lines = (delta / 120) * 3;
            if let Some(app) = G_APP.get() {
                if let Ok(mut s) = app.lock() {
                    let total = s
                        .connections
                        .iter()
                        .filter(|c| connection_matches(c, &s.search_query))
                        .count();
                    let max_scroll = total.saturating_sub(18);
                    if lines > 0 {
                        s.scroll_offset = s.scroll_offset.saturating_sub(lines as usize);
                    } else {
                        s.scroll_offset = (s.scroll_offset + (-lines) as usize).min(max_scroll);
                    }
                }
            }
            let _ = InvalidateRect(hwnd, None, FALSE);
            LRESULT(0)
        }
        WM_LBUTTONDOWN => {
            let x = (lparam.0 & 0xffff) as i32;
            let y = ((lparam.0 >> 16) & 0xffff) as i32;
            let mut rect = RECT::default();
            let _ = GetClientRect(hwnd, &mut rect);
            let _ = SetFocus(hwnd);
            if x >= rect.right - 36 && y <= 34 {
                toggle_popup();
                return LRESULT(0);
            }
            if y >= 4 && y <= 30 && x >= 480 && x <= rect.right - 50 {
                if let Some(app) = G_APP.get() {
                    if let Ok(mut s) = app.lock() {
                        s.search_active = true;
                    }
                }
                let _ = InvalidateRect(hwnd, None, FALSE);
                return LRESULT(0);
            }
            if y >= 72 && y <= 98 {
                if let Some(idx) = column_at(x, rect.right) {
                    let col = index_column(idx);
                    if let Some(app) = G_APP.get() {
                        if let Ok(mut s) = app.lock() {
                            if s.sort_col == col {
                                s.sort_dir = if s.sort_dir == SortDirection::Desc {
                                    SortDirection::Asc
                                } else {
                                    SortDirection::Desc
                                };
                            } else {
                                s.sort_col = col;
                                s.sort_dir = SortDirection::Desc;
                            }
                            s.scroll_offset = 0;
                        }
                    }
                    let _ = InvalidateRect(hwnd, None, FALSE);
                }
                return LRESULT(0);
            }
            if let Some(app) = G_APP.get() {
                if let Ok(mut s) = app.lock() {
                    s.search_active = false;
                }
            }
            LRESULT(0)
        }
        WM_KEYDOWN => {
            if wparam.0 == 27 {
                let mut had_text = false;
                if let Some(app) = G_APP.get() {
                    if let Ok(mut s) = app.lock() {
                        had_text = !s.search_query.is_empty();
                        if had_text {
                            s.search_query.clear();
                            s.scroll_offset = 0;
                        }
                    }
                }
                if had_text {
                    let _ = InvalidateRect(hwnd, None, FALSE);
                } else {
                    toggle_popup();
                }
            }
            LRESULT(0)
        }
        WM_CHAR => {
            let ch = wparam.0 as u32;
            if ch == 8 {
                let mut changed = false;
                if let Some(app) = G_APP.get() {
                    if let Ok(mut s) = app.lock() {
                        if s.search_active && !s.search_query.is_empty() {
                            s.search_query.pop();
                            s.scroll_offset = 0;
                            changed = true;
                        }
                    }
                }
                if changed {
                    let _ = InvalidateRect(hwnd, None, FALSE);
                }
            } else if ch >= 32 && ch != 127 {
                if let Some(c) = char::from_u32(ch) {
                    let mut changed = false;
                    if let Some(app) = G_APP.get() {
                        if let Ok(mut s) = app.lock() {
                            if s.search_active {
                                s.search_query.push(c);
                                s.scroll_offset = 0;
                                changed = true;
                            }
                        }
                    }
                    if changed {
                        let _ = InvalidateRect(hwnd, None, FALSE);
                    }
                }
            }
            LRESULT(0)
        }
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);
            let mut rect = RECT::default();
            let _ = GetClientRect(hwnd, &mut rect);
            let width = rect.right;
            let height = rect.bottom;

            let mem_dc = CreateCompatibleDC(hdc);
            let mem_bm = CreateCompatibleBitmap(hdc, width, height);
            let old_bm = SelectObject(mem_dc, mem_bm);

            fill_round(mem_dc, 0, 0, width, height, 8, rgb(11, 14, 19), rgb(38, 48, 64));
            fill_area(mem_dc, 1, 1, width - 1, 34, rgb(18, 23, 31));
            SetBkMode(mem_dc, TRANSPARENT);

            let mut conns_copy = Vec::new();
            let mut scroll_offset = 0usize;
            let mut total_upload = 0u64;
            let mut total_download = 0u64;
            let mut engine_memory = 0u64;
            let mut up_speed = 0u64;
            let mut down_speed = 0u64;
            let mut sort_col = SortColumn::TotalBytes;
            let mut sort_dir = SortDirection::Desc;
            let mut search_query = String::new();
            let mut search_active = false;
            if let Some(app) = G_APP.get() {
                if let Ok(s) = app.lock() {
                    conns_copy = s.connections.clone();
                    scroll_offset = s.scroll_offset;
                    total_upload = s.total_upload;
                    total_download = s.total_download;
                    engine_memory = s.engine_memory;
                    up_speed = s.up_bytes;
                    down_speed = s.down_bytes;
                    sort_col = s.sort_col;
                    sort_dir = s.sort_dir;
                    search_query = s.search_query.clone();
                    search_active = s.search_active;
                }
            }

            let total_count = conns_copy.len();
            let active_count = conns_copy.iter().filter(|c| c.is_active).count();
            let mut visible: Vec<ConnectionItem> = conns_copy
                .iter()
                .filter(|c| connection_matches(c, &search_query))
                .cloned()
                .collect();
            let matched_count = visible.len();
            sort_connections(&mut visible, sort_col, sort_dir);

            let title_font = create_font(17, 700);
            let old_font = SelectObject(mem_dc, title_font);
            draw_str(
                mem_dc,
                "SING-BOX REALTIME CONNECTION OBSERVATORY",
                14,
                0,
                470,
                34,
                rgb(148, 163, 184),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );
            draw_str(
                mem_dc,
                "✕",
                width - 36,
                0,
                width - 8,
                34,
                rgb(203, 213, 225),
                DT_CENTER | DT_VCENTER | DT_SINGLELINE,
            );
            SelectObject(mem_dc, old_font);
            let _ = DeleteObject(title_font);

            let search_border = if search_active {
                rgb(0, 210, 255)
            } else {
                rgb(51, 65, 85)
            };
            fill_round(mem_dc, 480, 4, width - 50, 30, 5, rgb(9, 12, 17), search_border);
            let search_text = if search_query.is_empty() {
                let mut hint = String::from("🔍 搜索: 域名/IP/规则/端口/协议... (Esc清空)");
                if search_active {
                    hint.push('|');
                }
                hint
            } else if search_active {
                format!("🔍 {}|", search_query)
            } else {
                format!("🔍 {}", search_query)
            };
            let search_color = if search_query.is_empty() {
                rgb(80, 96, 118)
            } else {
                rgb(226, 232, 240)
            };
            let search_font = create_font(13, 500);
            let old_search_font = SelectObject(mem_dc, search_font);
            draw_str(
                mem_dc,
                &search_text,
                492,
                4,
                width - 58,
                30,
                search_color,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            SelectObject(mem_dc, old_search_font);
            let _ = DeleteObject(search_font);

            let card_gap = 8;
            let card_w = (width - 24 - card_gap * 4) / 5;
            let card_y0 = 38;
            let card_y1 = 68;
            let card_font = create_font(13, 600);
            let old_card_font = SelectObject(mem_dc, card_font);

            let mut card_x = 12;
            fill_round(mem_dc, card_x, card_y0, card_x + card_w, card_y1, 6, rgb(15, 20, 28), rgb(35, 46, 64));
            draw_str(
                mem_dc,
                &format!("↑ UP: {}   ↓ DOWN: {}", format_bytes(total_upload), format_bytes(total_download)),
                card_x + 12,
                card_y0,
                card_x + card_w - 8,
                card_y1,
                rgb(0, 210, 255),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            card_x += card_w + card_gap;

            fill_round(mem_dc, card_x, card_y0, card_x + card_w, card_y1, 6, rgb(15, 20, 28), rgb(35, 46, 64));
            draw_str(
                mem_dc,
                &format!("⚡ LIVE: ↑ {} ↓ {}", format_speed(up_speed), format_speed(down_speed)),
                card_x + 12,
                card_y0,
                card_x + card_w - 8,
                card_y1,
                rgb(16, 240, 160),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            card_x += card_w + card_gap;

            fill_round(mem_dc, card_x, card_y0, card_x + card_w, card_y1, 6, rgb(15, 20, 28), rgb(35, 46, 64));
            draw_str(
                mem_dc,
                &format!("🧠 MEM: {}", format_bytes(engine_memory)),
                card_x + 12,
                card_y0,
                card_x + card_w - 8,
                card_y1,
                rgb(192, 132, 252),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            card_x += card_w + card_gap;

            fill_round(mem_dc, card_x, card_y0, card_x + card_w, card_y1, 6, rgb(15, 20, 28), rgb(35, 46, 64));
            draw_str(
                mem_dc,
                &format!("🌐 SESSIONS: {} / {}", active_count, total_count),
                card_x + 12,
                card_y0,
                card_x + card_w - 8,
                card_y1,
                rgb(251, 191, 36),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            card_x += card_w + card_gap;

            fill_round(mem_dc, card_x, card_y0, card_x + card_w, card_y1, 6, rgb(15, 20, 28), rgb(35, 46, 64));
            draw_str(
                mem_dc,
                &format!("🔎 MATCH: {} / {}", matched_count, total_count),
                card_x + 12,
                card_y0,
                card_x + card_w - 8,
                card_y1,
                rgb(56, 189, 248),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );

            SelectObject(mem_dc, old_card_font);
            let _ = DeleteObject(card_font);

            let headers = [
                "TIME",
                "DUR",
                "PROTO/IN",
                "SOURCE",
                "TARGET HOST / DEST",
                "CHAIN / RULE",
                "LIVE SPEED",
                "TOTAL I/O",
                "STATE",
            ];
            let sorted_index = column_index(sort_col);
            let col_font = create_font(13, 700);
            let old_col_font = SelectObject(mem_dc, col_font);
            for idx in 0..9 {
                let left = column_left(idx, width);
                let right = column_right(idx, width) - 4;
                let fmt = if idx >= 6 {
                    DT_RIGHT | DT_VCENTER | DT_SINGLELINE
                } else {
                    DT_LEFT | DT_VCENTER | DT_SINGLELINE
                };
                let label = if idx == sorted_index {
                    let arrow = if sort_dir == SortDirection::Desc { "▼" } else { "▲" };
                    format!("{} {}", headers[idx], arrow)
                } else {
                    headers[idx].to_string()
                };
                let color = if idx == sorted_index {
                    rgb(56, 189, 248)
                } else {
                    rgb(100, 116, 139)
                };
                draw_str(mem_dc, &label, left, 72, right, 98, color, fmt);
            }
            SelectObject(mem_dc, old_col_font);
            let _ = DeleteObject(col_font);

            let row_font = create_font(14, 500);
            let old_rf = SelectObject(mem_dc, row_font);

            let row_start = 102;
            let row_height = 30;
            let max_rows = (((height - row_start - 8) / row_height).max(1)) as usize;
            let skip_count = scroll_offset.min(visible.len().saturating_sub(1));
            let mut y_offset = row_start;
            for (idx, conn) in visible.iter().skip(skip_count).take(max_rows).enumerate() {
                if y_offset + row_height > height - 6 {
                    break;
                }
                if idx % 2 == 1 {
                    fill_area(mem_dc, 4, y_offset, width - 8, y_offset + row_height, rgb(15, 19, 26));
                }

                let time_str = parse_time(&conn.start);
                let dur_str = format_duration(conn.duration_secs);
                let proto_str = format_proto(&conn.metadata.network, &conn.metadata.inbound_type);
                let source_str = if !conn.metadata.source_ip.is_empty() {
                    format!("{}:{}", conn.metadata.source_ip, conn.metadata.source_port)
                } else {
                    "-".to_string()
                };
                let target_str = if !conn.metadata.host.is_empty() {
                    format!("{}:{}", conn.metadata.host, conn.metadata.destination_port)
                } else if !conn.metadata.destination_ip.is_empty() {
                    format!(
                        "{}:{}",
                        conn.metadata.destination_ip, conn.metadata.destination_port
                    )
                } else {
                    "-".to_string()
                };
                let chain = conn.chains.first().cloned().unwrap_or_else(|| "-".to_string());
                let rule_str = format_rule(&conn.rule, &chain);
                let live_str = format!(
                    "↑ {} ↓ {}",
                    format_speed(conn.cur_up_speed),
                    format_speed(conn.cur_down_speed)
                );
                let io_str = format!(
                    "↑ {} ↓ {}",
                    format_bytes(conn.upload),
                    format_bytes(conn.download)
                );
                let state_str = if !conn.is_active {
                    "CLOSED"
                } else if conn.is_idle {
                    "IDLE"
                } else {
                    "ACTIVE"
                };

                let (c_time, c_dur, c_proto, c_src, c_tgt, c_rule, c_live, c_io, c_state) =
                    if !conn.is_active {
                        (
                            rgb(75, 88, 105),
                            rgb(75, 88, 105),
                            rgb(75, 88, 105),
                            rgb(100, 115, 135),
                            rgb(115, 130, 150),
                            rgb(85, 100, 118),
                            rgb(85, 100, 118),
                            rgb(85, 100, 118),
                            rgb(100, 116, 139),
                        )
                    } else if conn.is_idle {
                        (
                            rgb(148, 163, 184),
                            rgb(56, 189, 248),
                            rgb(167, 139, 250),
                            rgb(148, 163, 184),
                            rgb(203, 213, 225),
                            rgb(148, 163, 184),
                            rgb(251, 191, 36),
                            rgb(148, 163, 184),
                            rgb(251, 191, 36),
                        )
                    } else {
                        let out_c = if chain == "direct" {
                            rgb(148, 163, 184)
                        } else {
                            rgb(16, 185, 129)
                        };
                        (
                            rgb(148, 163, 184),
                            rgb(56, 189, 248),
                            rgb(167, 139, 250),
                            rgb(148, 163, 184),
                            rgb(248, 250, 252),
                            out_c,
                            rgb(0, 210, 255),
                            rgb(0, 210, 255),
                            rgb(0, 210, 255),
                        )
                    };

                let texts = [
                    time_str,
                    dur_str,
                    proto_str,
                    source_str,
                    target_str,
                    rule_str,
                    live_str,
                    io_str,
                    state_str.to_string(),
                ];
                let colors = [c_time, c_dur, c_proto, c_src, c_tgt, c_rule, c_live, c_io, c_state];
                for col in 0..9 {
                    let left = column_left(col, width);
                    let right = column_right(col, width) - 4;
                    let fmt = if col >= 6 {
                        DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
                    } else {
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
                    };
                    draw_str(
                        mem_dc,
                        &texts[col],
                        left,
                        y_offset,
                        right,
                        y_offset + row_height,
                        colors[col],
                        fmt,
                    );
                }

                y_offset += row_height;
            }

            if matched_count > max_rows {
                let track_top = row_start;
                let track_h = height - track_top - 8;
                let thumb_h = ((max_rows as f32 / matched_count as f32) * track_h as f32).max(20.0) as i32;
                let max_s = (matched_count - max_rows) as f32;
                let thumb_top =
                    track_top + ((skip_count as f32 / max_s) * (track_h - thumb_h) as f32) as i32;
                fill_area(
                    mem_dc,
                    width - 6,
                    thumb_top,
                    width - 2,
                    thumb_top + thumb_h,
                    rgb(50, 65, 85),
                );
            }

            let _ = BitBlt(hdc, 0, 0, width, height, mem_dc, 0, 0, SRCCOPY);
            SelectObject(mem_dc, old_rf);
            let _ = DeleteObject(row_font);
            SelectObject(mem_dc, old_bm);
            let _ = DeleteObject(mem_bm);
            let _ = DeleteDC(mem_dc);
            let _ = EndPaint(hwnd, &ps);
            LRESULT(0)
        }
        _ => DefWindowProcA(hwnd, msg, wparam, lparam),
    }
}

fn main() -> Result<()> {
    let _guard = SingboxGuard;
    unsafe {
        let _ = SetConsoleCtrlHandler(Some(console_ctrl_handler), BOOL(1));
        let app = Arc::new(Mutex::new(BarApp {
            up_bytes: 0,
            down_bytes: 0,
            connected: false,
            popup_visible: false,
            connections: Vec::new(),
            scroll_offset: 0,
            total_upload: 0,
            total_download: 0,
            engine_memory: 0,
            sort_col: SortColumn::TotalBytes,
            sort_dir: SortDirection::Desc,
            search_query: String::new(),
            search_active: false,
            menu_open: false,
            menu_anim: 0.0,
            hover_btn: None,
            active_sub_name: active_subscription_name(),
        }));
        let _ = G_APP.set(app.clone());

        std::thread::spawn(|| {
            ensure_singbox_running();
        });

        let bg_app = app.clone();
        std::thread::spawn(move || {
            stream_traffic(bg_app);
        });

        let poll_app = app.clone();
        std::thread::spawn(move || {
            poll_connections_bg(poll_app);
        });

        let log_app = app.clone();
        start_telemetry_logger(log_app);

        let instance = GetModuleHandleW(None)?;
        let app_icon = LoadIconW(instance, PCWSTR(1 as *const u16)).unwrap_or_default();

        let bar_class = s!("singbox_bar_class");
        let bar_wc = WNDCLASSA {
            style: CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS,
            lpfnWndProc: Some(wndproc_bar),
            hInstance: instance.into(),
            hIcon: app_icon,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            lpszClassName: bar_class,
            ..Default::default()
        };
        let _ = RegisterClassA(&bar_wc);

        let popup_class = s!("singbox_popup_class");
        let popup_wc = WNDCLASSA {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc_popup),
            hInstance: instance.into(),
            hIcon: app_icon,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            lpszClassName: popup_class,
            ..Default::default()
        };
        let _ = RegisterClassA(&popup_wc);

        let bar_w = 210;
        let bar_h = 26;
        let bar_x = 0;
        let bar_y = 0;

        let bar_hwnd = CreateWindowExA(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
            bar_class,
            s!("singbox_bar"),
            WS_POPUP,
            bar_x,
            bar_y,
            bar_w,
            bar_h,
            None,
            None,
            instance,
            None,
        )?;

        let popup_w = 1180;
        let popup_h = 660;
        let popup_x = 10;
        let popup_y = bar_h + 4;

        let popup_hwnd = CreateWindowExA(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
            popup_class,
            s!("singbox_popup"),
            WS_POPUP,
            popup_x,
            popup_y,
            popup_w,
            popup_h,
            None,
            None,
            instance,
            None,
        )?;

        G_BAR_HWND.store(bar_hwnd.0 as isize, Ordering::Relaxed);
        G_POPUP_HWND.store(popup_hwnd.0 as isize, Ordering::Relaxed);

        let corner_preference = 2u32;
        let _ = DwmSetWindowAttribute(
            bar_hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            &corner_preference as *const _ as *const _,
            std::mem::size_of::<u32>() as u32,
        );
        let _ = DwmSetWindowAttribute(
            popup_hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            &corner_preference as *const _ as *const _,
            std::mem::size_of::<u32>() as u32,
        );

        let backdrop_type = DWM_SYSTEMBACKDROP_TYPE(4);
        let _ = DwmSetWindowAttribute(
            bar_hwnd,
            DWMWA_SYSTEMBACKDROP_TYPE,
            &backdrop_type as *const _ as *const _,
            std::mem::size_of::<u32>() as u32,
        );
        let _ = DwmSetWindowAttribute(
            popup_hwnd,
            DWMWA_SYSTEMBACKDROP_TYPE,
            &backdrop_type as *const _ as *const _,
            std::mem::size_of::<u32>() as u32,
        );

        let _ = SetLayeredWindowAttributes(bar_hwnd, COLORREF(0), 242, LWA_ALPHA);
        let _ = SetLayeredWindowAttributes(popup_hwnd, COLORREF(0), 246, LWA_ALPHA);

        let _ = SetTimer(bar_hwnd, 1, 120, None);

        let _ = ShowWindow(bar_hwnd, SW_SHOW);

        let mut msg = MSG::default();
        while GetMessageA(&mut msg, None, 0, 0).into() {
            let _ = TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        Ok(())
    }
}
