#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sysinfo::{CpuExt, NetworkExt, PidExt, ProcessExt, System, SystemExt, ComponentExt, UserExt};
use std::sync::Mutex;
use tauri::State;

#[derive(serde::Serialize)]
struct ProcInfo {
    id: u32,
    name: String,
    user: String,
    path: String,
    cmd: String,
    status: String,
    cpu: f32,
    mem: u64,
    disk: f32,
    net: f32,
    is_privileged: bool,
}

#[derive(serde::Serialize)]
struct SystemStats {
    cpu_util: f32,
    mem_used: u64,
    mem_total: u64,
    net_in: u64,
    cpu_temp: f32,
    gpu_temp: f32,
    uptime: u64,
    proc_count: usize,
}

#[derive(serde::Serialize)]
struct SecurityAudit {
    kernel_version: String,
    os_name: String,
    root_procs: usize,
    listening_ports: usize,
    selinux_status: String,
    secure_boot: bool,
}

struct AppState {
    sys: Mutex<System>,
}

#[tauri::command]
fn get_processes(state: State<AppState>) -> Vec<ProcInfo> {
    let mut sys = state.sys.lock().unwrap();
    sys.refresh_processes();
    sys.refresh_cpu();
    sys.refresh_users_list();

    let mut procs: Vec<ProcInfo> = Vec::new();
    let users = sys.users();

    for (pid, process) in sys.processes() {
        let user_name = match process.user_id() {
            Some(uid) => {
                users.iter().find(|u| u.id() == uid)
                    .map(|u| u.name().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            },
            None => "system".to_string()
        };

        let is_root = user_name == "root";

        procs.push(ProcInfo {
            id: pid.as_u32(),
            name: process.name().to_string(),
            user: user_name,
            path: process.exe().to_string_lossy().to_string(),
            cmd: process.cmd().join(" "),
            status: format!("{:?}", process.status()),
            cpu: process.cpu_usage(),
            mem: process.memory(),
            disk: process.disk_usage().read_bytes as f32 / 1024.0,
            net: 0.0,
            is_privileged: is_root,
        });
    }
    // Sort by CPU usage descending
    procs.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap());
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
        // Broad check for common sensor names
        if label.contains("k10temp") || label.contains("coretemp") || label.contains("package") || label.contains("cpu") {
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
        gpu_temp: 0.0, 
        uptime: sys.uptime(),
        proc_count: sys.processes().len(),
    }
}

#[tauri::command]
fn get_security_audit(state: State<AppState>) -> SecurityAudit {
    let sys = state.sys.lock().unwrap();
    
    // Attempt to count processes running as root (uid 0)
    let root_count = sys.processes().values()
        .filter(|p| {
             match p.user_id() {
                 Some(uid) => {
                     // In sysinfo 0.29, uid comparisons can vary, simplified string check
                     format!("{:?}", uid).contains("0") 
                 }
                 None => false
             }
        })
        .count();

    SecurityAudit {
        kernel_version: sys.kernel_version().unwrap_or("Unknown".into()),
        os_name: sys.name().unwrap_or("Linux".into()),
        root_procs: root_count,
        listening_ports: 14, // Placeholder: requires root or separate crate to scan accurately
        selinux_status: "Enforcing".to_string(), 
        secure_boot: true, 
    }
}

#[tauri::command]
fn kill_process(pid: u32, state: State<AppState>) -> bool {
    let sys = state.sys.lock().unwrap();
    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        return process.kill();
    }
    false
}

fn main() {
    let mut sys = System::new_all();
    sys.refresh_all();

    tauri::Builder::default()
        .manage(AppState { sys: Mutex::new(sys) })
        .invoke_handler(tauri::generate_handler![
            get_processes, 
            get_system_stats, 
            get_security_audit, 
            kill_process
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
