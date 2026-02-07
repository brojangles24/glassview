#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sysinfo::{CpuExt, System, SystemExt, ProcessExt, PidExt, UserExt, NetworkExt, ComponentExt};
use std::sync::Mutex;
use std::process::Command;
use std::fs;
use tauri::{State, SystemTray, SystemTrayMenu, SystemTrayEvent, CustomMenuItem, Manager};

// --- Structs ---

#[derive(serde::Serialize)]
struct ProcInfo {
    id: u32,
    name: String,
    user: String,
    status: String,
    cpu: f32,
    mem: u64,
}

#[derive(serde::Serialize)]
struct SystemStats {
    cpu_util: f32,
    mem_used: u64,
    mem_total: u64,
    net_in: u64,
    cpu_temp: f32,
    uptime: u64,
    proc_count: usize,
}

#[derive(serde::Serialize)]
struct SecurityAudit {
    kernel_version: String,
    secure_boot: bool,
    root_procs: usize,
}

#[derive(serde::Serialize)]
struct ServiceStatus {
    name: String,
    status: String,
    active: bool,
}

#[derive(serde::Serialize)]
struct LogEntry {
    time: String,
    msg: String,
}

#[derive(serde::Serialize)]
struct StartupApp {
    name: String,
    path: String,
    enabled: bool,
}

#[derive(serde::Serialize)]
struct HardwareInfo {
    cpu_model: String,
    cpu_cores: usize,
    ram_total: String,
    gpu_model: String,
    os_distro: String,
}

struct AppState {
    sys: Mutex<System>,
}

// --- Commands ---

#[tauri::command]
fn get_processes(state: State<AppState>) -> Vec<ProcInfo> {
    let mut sys = state.sys.lock().unwrap();
    sys.refresh_processes();
    sys.refresh_cpu();
    
    let mut procs: Vec<ProcInfo> = Vec::new();
    let users = sys.users();

    for (pid, process) in sys.processes() {
        let user_name = match process.user_id() {
             Some(uid) => users.iter().find(|u| u.id() == uid)
                 .map(|u| u.name().to_string())
                 .unwrap_or_else(|| "unknown".to_string()),
             None => "system".to_string()
        };

        procs.push(ProcInfo {
            id: pid.as_u32(),
            name: process.name().to_string(),
            user: user_name,
            status: format!("{:?}", process.status()),
            cpu: process.cpu_usage(),
            mem: process.memory(),
        });
    }
    procs.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
    procs.into_iter().take(60).collect()
}

#[tauri::command]
fn get_system_stats(state: State<AppState>) -> SystemStats {
    let mut sys = state.sys.lock().unwrap();
    sys.refresh_cpu();
    sys.refresh_memory();
    sys.refresh_networks();
    sys.refresh_components();

    let mut net_total = 0;
    for (_name, data) in sys.networks() {
        net_total += data.received();
    }

    let mut cpu_t = 0.0;
    for component in sys.components() {
        let label = component.label().to_lowercase();
        if label.contains("cpu") || label.contains("core") || label.contains("package") {
            cpu_t = component.temperature();
            break;
        }
    }

    SystemStats {
        cpu_util: sys.global_cpu_info().cpu_usage(),
        mem_used: sys.used_memory(),
        mem_total: sys.total_memory(),
        net_in: net_total,
        cpu_temp: cpu_t,
        uptime: sys.uptime(),
        proc_count: sys.processes().len(),
    }
}

#[tauri::command]
fn get_startup_apps() -> Vec<StartupApp> {
    let mut apps = Vec::new();
    let home = std::env::var("HOME").unwrap_or_default();
    let path = format!("{}/.config/autostart", home);

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.ends_with(".desktop") {
                apps.push(StartupApp {
                    name: fname.replace(".desktop", ""),
                    path: entry.path().to_string_lossy().to_string(),
                    enabled: true,
                });
            } else if fname.ends_with(".desktop.bak") {
                apps.push(StartupApp {
                    name: fname.replace(".desktop.bak", ""),
                    path: entry.path().to_string_lossy().to_string(),
                    enabled: false,
                });
            }
        }
    }
    apps
}

#[tauri::command]
fn toggle_startup(path: String, enable: bool) -> bool {
    let new_path = if enable {
        path.replace(".desktop.bak", ".desktop")
    } else {
        path.replace(".desktop", ".desktop.bak")
    };
    fs::rename(path, new_path).is_ok()
}

#[tauri::command]
fn get_hardware_info(state: State<AppState>) -> HardwareInfo {
    let sys = state.sys.lock().unwrap();
    let gpu_out = Command::new("lspci").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines()
            .find(|l| l.contains("VGA") || l.contains("3D"))
            .map(|l| l.split(": ").last().unwrap_or("Unknown GPU").to_string())
            .unwrap_or("Integrated/Unknown".to_string()))
        .unwrap_or("Unknown".to_string());

    HardwareInfo {
        cpu_model: sys.global_cpu_info().brand().to_string(),
        cpu_cores: sys.cpus().len(),
        ram_total: format!("{:.1} GB", sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0),
        gpu_model: gpu_out,
        os_distro: sys.name().unwrap_or("Linux".into()),
    }
}

#[tauri::command]
fn control_service(name: String, action: String) -> bool {
    Command::new("systemctl").arg(&action).arg(&name).status().map(|s| s.success()).unwrap_or(false)
}

#[tauri::command]
fn get_services() -> Vec<ServiceStatus> {
    let services = vec!["sshd", "NetworkManager", "ufw", "docker", "bluetooth", "cronie"];
    let mut results = Vec::new();
    for s in services {
        let output = Command::new("systemctl").arg("is-active").arg(s).output();
        let status = match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "unknown".to_string(),
        };
        results.push(ServiceStatus { name: s.to_string(), active: status == "active", status });
    }
    results
}

#[tauri::command]
fn get_security_audit(state: State<AppState>) -> SecurityAudit {
    let sys = state.sys.lock().unwrap();
    let root_count = sys.processes().values()
        .filter(|p| format!("{:?}", p.user_id()).contains("0"))
        .count();

    SecurityAudit {
        kernel_version: sys.kernel_version().unwrap_or("Unknown".into()),
        secure_boot: true,
        root_procs: root_count,
    }
}

#[tauri::command]
fn get_journal_logs() -> Vec<LogEntry> {
    let output = Command::new("journalctl").args(&["-p", "3", "-n", "10", "--output=short-iso", "--no-pager"]).output();
    let mut logs = Vec::new();
    if let Ok(o) = output {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            logs.push(LogEntry { time: "Recent".into(), msg: line.to_string() });
        }
    }
    logs
}

#[tauri::command]
fn kill_process(pid: u32, state: State<AppState>) -> bool {
    let sys = state.sys.lock().unwrap();
    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        return process.kill();
    }
    false
}

// --- NEW PROCESS CONTROLS ---

#[tauri::command]
fn suspend_process(pid: u32) -> bool {
    // SIGSTOP = 19
    Command::new("kill").arg("-19").arg(pid.to_string()).status().map(|s| s.success()).unwrap_or(false)
}

#[tauri::command]
fn resume_process(pid: u32) -> bool {
    // SIGCONT = 18
    Command::new("kill").arg("-18").arg(pid.to_string()).status().map(|s| s.success()).unwrap_or(false)
}

#[tauri::command]
fn set_process_priority(pid: u32, priority: String) -> bool {
    // renice -n <value> -p <pid>
    // High = -10, Normal = 0, Low = 10
    let val = match priority.as_str() {
        "High" => "-10",
        "Low" => "10",
        _ => "0",
    };
    Command::new("renice").arg("-n").arg(val).arg("-p").arg(pid.to_string()).status().map(|s| s.success()).unwrap_or(false)
}

fn main() {
    let mut sys = System::new_all();
    sys.refresh_all();

    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    let show = CustomMenuItem::new("show".to_string(), "Show Dashboard");
    let tray_menu = SystemTrayMenu::new().add_item(show).add_item(quit);
    let tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .manage(AppState { sys: Mutex::new(sys) })
        .system_tray(tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => {
                match id.as_str() {
                    "quit" => { std::process::exit(0); }
                    "show" => {
                        let window = app.get_window("main").unwrap();
                        window.show().unwrap();
                        window.set_focus().unwrap();
                    }
                    _ => {}
                }
            }
            SystemTrayEvent::LeftClick { .. } => {
                let window = app.get_window("main").unwrap();
                window.show().unwrap();
                window.set_focus().unwrap();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            get_processes, get_system_stats, get_security_audit,
            get_journal_logs, get_services, control_service, 
            get_startup_apps, toggle_startup, get_hardware_info, 
            kill_process, suspend_process, resume_process, set_process_priority
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
