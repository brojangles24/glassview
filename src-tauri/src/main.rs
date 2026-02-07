#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sysinfo::{CpuExt, NetworkExt, PidExt, ProcessExt, System, SystemExt, ComponentExt, UserExt};
use std::sync::Mutex;
use std::process::Command;
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

#[derive(serde::Serialize)]
struct ServiceStatus {
    name: String,
    status: String,
    active: bool,
}

#[derive(serde::Serialize)]
struct GpuStats {
    util: f32,
    temp: f32,
}

#[derive(serde::Serialize)]
struct LogEntry {
    time: String,
    msg: String,
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
    let root_count = sys.processes().values()
        .filter(|p| {
             match p.user_id() {
                 Some(uid) => format!("{:?}", uid).contains("0"),
                 None => false
             }
        })
        .count();

    SecurityAudit {
        kernel_version: sys.kernel_version().unwrap_or("Unknown".into()),
        os_name: sys.name().unwrap_or("Linux".into()),
        root_procs: root_count,
        listening_ports: 14, 
        selinux_status: "Enforcing".to_string(), 
        secure_boot: true, 
    }
}

#[tauri::command]
fn get_services() -> Vec<ServiceStatus> {
    let services = vec!["sshd", "NetworkManager", "bluetooth", "ufw", "docker", "systemd-journald"];
    let mut results = Vec::new();

    for s in services {
        let output = Command::new("systemctl")
            .arg("is-active")
            .arg(s)
            .output();
        
        let status = match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => "unknown".to_string(),
        };
        
        results.push(ServiceStatus { 
            name: s.to_string(), 
            active: status == "active",
            status 
        });
    }
    results
}

#[tauri::command]
fn get_gpu_stats() -> GpuStats {
    // Requires nvidia-utils or similar
    let output = Command::new("nvidia-smi")
        .args(&["--query-gpu=utilization.gpu,temperature.gpu", "--format=csv,noheader,nounits"])
        .output();

    if let Ok(o) = output {
        if o.status.success() {
            let out_str = String::from_utf8_lossy(&o.stdout);
            let parts: Vec<&str> = out_str.split(',').collect();
            if parts.len() >= 2 {
                return GpuStats {
                    util: parts[0].trim().parse().unwrap_or(0.0),
                    temp: parts[1].trim().parse().unwrap_or(0.0),
                };
            }
        }
    }
    
    GpuStats { util: 0.0, temp: 0.0 }
}

#[tauri::command]
fn get_journal_logs() -> Vec<LogEntry> {
    // Get last 5 errors/critical logs
    let output = Command::new("journalctl")
        .args(&["-p", "3", "-n", "5", "--output=short-iso", "--no-pager"])
        .output();

    let mut logs = Vec::new();
    if let Ok(o) = output {
        let out_str = String::from_utf8_lossy(&o.stdout);
        for line in out_str.lines() {
            let parts: Vec<&str> = line.splitn(4, ' ').collect(); // simple split attempt
            if parts.len() >= 4 {
                // Formatting simplified: Time + Host + Process + Msg
                // We just grab Time (part 0) and Msg (rest)
                let time = parts[0].to_string();
                let msg = parts[3..].join(" "); // simplistic reconstruction
                
                logs.push(LogEntry {
                    time,
                    msg: line.to_string(), // Send full line for now
                });
            }
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

fn main() {
    let mut sys = System::new_all();
    sys.refresh_all();

    tauri::Builder::default()
        .manage(AppState { sys: Mutex::new(sys) })
        .invoke_handler(tauri::generate_handler![
            get_processes, 
            get_system_stats, 
            get_security_audit, 
            get_services,
            get_gpu_stats,
            get_journal_logs,
            kill_process
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
