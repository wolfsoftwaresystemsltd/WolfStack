use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::{info, error};
use rand::Rng;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VmConfig {
    pub name: String,
    pub cpus: u32,
    pub memory_mb: u32,
    pub disk_size_gb: u32,
    pub iso_path: Option<String>,
    pub running: bool,
    pub vnc_port: Option<u16>,
    #[serde(default)]
    pub vnc_ws_port: Option<u16>,
    pub mac_address: Option<String>,
    pub auto_start: bool,
    #[serde(default)]
    pub wolfnet_ip: Option<String>,
}

impl VmConfig {
    pub fn new(name: String, cpus: u32, memory_mb: u32, disk_size_gb: u32) -> Self {
        VmConfig {
            name,
            cpus,
            memory_mb,
            disk_size_gb,
            iso_path: None,
            running: false,
            vnc_port: None,
            vnc_ws_port: None,
            mac_address: Some(generate_mac()),
            auto_start: false,
            wolfnet_ip: None,
        }
    }
}

fn generate_mac() -> String {
    let mut rng = rand::thread_rng();
    format!("52:54:00:{:02x}:{:02x}:{:02x}", rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>())
}

pub struct VmManager {
    pub base_dir: PathBuf,
}

impl VmManager {
    pub fn new() -> Self {
        let base_dir = PathBuf::from("/var/lib/wolfstack/vms");
        if let Err(e) = fs::create_dir_all(&base_dir) {
            error!("Failed to create VM directory: {}", e);
        }
        VmManager { base_dir }
    }

    pub fn list_vms(&self) -> Vec<VmConfig> {
        let mut vms = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                 let path = entry.path();
                 if path.extension().and_then(|e| e.to_str()) == Some("json") {
                     if let Ok(content) = fs::read_to_string(&path) {
                         if let Ok(mut vm) = serde_json::from_str::<VmConfig>(&content) {
                             vm.running = self.check_running(&vm.name);
                             if vm.running {
                                 vm.vnc_port = self.read_runtime_vnc_port(&vm.name);
                                 vm.vnc_ws_port = self.read_runtime_ws_port(&vm.name);
                             } else {
                                 vm.vnc_port = None;
                                 vm.vnc_ws_port = None;
                             }
                             vms.push(vm);
                         }
                     }
                 }
            }
        }
        vms
    }

    fn vm_config_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", name))
    }
    
    fn vm_disk_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.qcow2", name))
    }

    /// TAP interface name for a VM
    fn tap_name(name: &str) -> String {
        // TAP names limited to 15 chars
        let short = if name.len() > 11 { &name[..11] } else { name };
        format!("tap-{}", short)
    }

    pub fn create_vm(&self, mut config: VmConfig) -> Result<(), String> {
        if self.vm_config_path(&config.name).exists() {
            return Err("VM already exists".to_string());
        }

        // Validation
        if config.cpus == 0 { config.cpus = 1; }
        if config.memory_mb == 0 { config.memory_mb = 1024; }
        if config.disk_size_gb == 0 { config.disk_size_gb = 10; }

        // Validate WolfNet IP if provided
        if let Some(ref ip) = config.wolfnet_ip {
            let ip = ip.trim();
            if !ip.is_empty() {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() != 4 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
                    return Err(format!("Invalid WolfNet IP: '{}' — must be like 10.10.10.100", ip));
                }
                config.wolfnet_ip = Some(ip.to_string());
            } else {
                config.wolfnet_ip = None;
            }
        }

        let disk_path = self.vm_disk_path(&config.name);
        
        // Create disk
        let output = Command::new("qemu-img")
            .arg("create")
            .arg("-f")
            .arg("qcow2")
            .arg(&disk_path)
            .arg(format!("{}G", config.disk_size_gb))
            .output()
            .map_err(|e| e.to_string())?;
        
        if !output.status.success() {
             return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }

        // Save config
        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(self.vm_config_path(&config.name), json).map_err(|e| e.to_string())?;
        
        info!("Created VM: {} (WolfNet: {:?})", config.name, config.wolfnet_ip);
        Ok(())
    }

    /// Update VM settings (must be stopped)
    pub fn update_vm(&self, name: &str, cpus: Option<u32>, memory_mb: Option<u32>, 
                     iso_path: Option<String>, wolfnet_ip: Option<String>,
                     disk_size_gb: Option<u32>) -> Result<(), String> {
        if self.check_running(name) {
            return Err("Cannot edit VM while it is running. Stop it first.".to_string());
        }

        let config_path = self.vm_config_path(name);
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("VM not found: {}", e))?;
        let mut config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config: {}", e))?;

        if let Some(c) = cpus { if c > 0 { config.cpus = c; } }
        if let Some(m) = memory_mb { if m >= 256 { config.memory_mb = m; } }
        
        // ISO: accept empty string to clear, or a path to set
        if let Some(ref iso) = iso_path {
            if iso.is_empty() {
                config.iso_path = None;
            } else {
                config.iso_path = Some(iso.clone());
            }
        }

        // WolfNet IP: accept empty string to clear
        if let Some(ref ip) = wolfnet_ip {
            if ip.is_empty() {
                config.wolfnet_ip = None;
            } else {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() != 4 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
                    return Err(format!("Invalid WolfNet IP: '{}'", ip));
                }
                config.wolfnet_ip = Some(ip.clone());
            }
        }

        // Disk resize (grow only)
        if let Some(new_size) = disk_size_gb {
            if new_size > config.disk_size_gb {
                let disk_path = self.vm_disk_path(name);
                let output = Command::new("qemu-img")
                    .args(["resize", &disk_path.to_string_lossy(), &format!("{}G", new_size)])
                    .output()
                    .map_err(|e| format!("Disk resize failed: {}", e))?;
                if !output.status.success() {
                    return Err(format!("Disk resize failed: {}", String::from_utf8_lossy(&output.stderr)));
                }
                config.disk_size_gb = new_size;
                info!("Resized VM {} disk to {}G", name, new_size);
            }
        }

        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&config_path, json).map_err(|e| e.to_string())?;
        
        info!("Updated VM: {}", name);
        Ok(())
    }

    pub fn start_vm(&self, name: &str) -> Result<(), String> {
        if self.check_running(name) {
             return Err("VM already running".to_string());
        }

        let config_path = self.vm_config_path(name);
        let log_path = self.base_dir.join(format!("{}.log", name));

        // Helper: append to log file
        let write_log = |msg: &str| {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
                let _ = writeln!(f, "[{}] {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
            }
        };

        write_log(&format!("=== Starting VM '{}' ===", name));

        let content = fs::read_to_string(&config_path)
            .map_err(|e| { 
                let msg = format!("VM config not found: {}", e);
                write_log(&msg); msg
            })?;
        let config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| {
                let msg = format!("Invalid VM config: {}", e);
                write_log(&msg); msg
            })?;

        write_log(&format!("Config: cpus={}, memory={}MB, disk={}GB, iso={:?}, wolfnet_ip={:?}", 
                  config.cpus, config.memory_mb, config.disk_size_gb, config.iso_path, config.wolfnet_ip));

        // Check if qemu-system-x86_64 is available
        let qemu_check = Command::new("which").arg("qemu-system-x86_64").output();
        let qemu_path = match &qemu_check {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => {
                let msg = "qemu-system-x86_64 not found. Install QEMU: apt install qemu-system-x86 qemu-utils";
                write_log(msg);
                return Err(msg.to_string());
            }
        };
        write_log(&format!("QEMU binary: {}", qemu_path));

        let mut rng = rand::thread_rng();
        let vnc_num: u16 = rng.gen_range(10..99); 
        let vnc_port: u16 = 5900 + vnc_num;
        let ws_port: u16 = 6080 + vnc_num;  // WebSocket port for noVNC
        let vnc_arg = format!("0.0.0.0:{},websocket=0.0.0.0:{}", vnc_num, ws_port);
        
        write_log(&format!("VNC display :{} (port {}), WebSocket port {}", vnc_num, vnc_port, ws_port));

        // Check if KVM is available
        let kvm_available = std::path::Path::new("/dev/kvm").exists();
        write_log(&format!("KVM available: {}", kvm_available));
        if !kvm_available {
            info!("KVM not available for VM {} — using software emulation (slower)", name);
        }

        let disk_path = self.vm_disk_path(name);
        if !disk_path.exists() {
            let msg = format!("Disk image not found: {}", disk_path.display());
            write_log(&msg);
            return Err(msg);
        }
        write_log(&format!("Disk: {} (exists)", disk_path.display()));

        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.arg("-name").arg(name)
           .arg("-m").arg(format!("{}M", config.memory_mb))
           .arg("-smp").arg(format!("{}", config.cpus))
           .arg("-drive").arg(format!("file={},format=qcow2,if=virtio", disk_path.display()))
           .arg("-vnc").arg(&vnc_arg)
           .arg("-daemonize");

        // KVM or software emulation
        if kvm_available {
            cmd.arg("-enable-kvm").arg("-cpu").arg("host");
        } else {
            cmd.arg("-cpu").arg("qemu64");
        }

        // Networking: VMs configure their own IP inside the guest OS.
        // If WolfNet IP is set, try TAP networking for direct L2 access.
        // Otherwise (or if TAP fails), use user-mode networking which always works.
        let mut using_tap = false;
        if let Some(ref wolfnet_ip) = config.wolfnet_ip {
            let tap = Self::tap_name(name);
            write_log(&format!("Attempting TAP networking for WolfNet IP {} (configure this IP inside the guest OS)", wolfnet_ip));
            
            match self.setup_tap(&tap) {
                Ok(_) => {
                    write_log(&format!("TAP '{}' created successfully", tap));
                    cmd.arg("-netdev").arg(format!("tap,id=net0,ifname={},script=no,downscript=no", tap))
                       .arg("-device").arg("virtio-net-pci,netdev=net0");
                    
                    if let Err(e) = self.setup_wolfnet_routing(&tap, wolfnet_ip) {
                        write_log(&format!("WolfNet routing warning: {} (VM will still start)", e));
                    } else {
                        write_log(&format!("WolfNet routing configured for {} via {}", wolfnet_ip, tap));
                    }
                    using_tap = true;
                    info!("VM {} using TAP {} with WolfNet IP {}", name, tap, wolfnet_ip);
                }
                Err(e) => {
                    write_log(&format!("TAP setup failed: {} — falling back to user-mode networking", e));
                    write_log("Note: You can still configure the WolfNet IP inside the guest OS manually");
                    info!("TAP setup failed for VM {}: {} — using user-mode", name, e);
                }
            }
        }
        
        if !using_tap {
            write_log("Networking: user-mode (NAT, VM can access host network)");
            cmd.arg("-netdev").arg("user,id=net0")
               .arg("-device").arg("virtio-net-pci,netdev=net0");
        }

        if let Some(iso) = &config.iso_path {
             if !iso.is_empty() {
                 if !std::path::Path::new(iso).exists() {
                     let msg = format!("ISO file not found: {}", iso);
                     write_log(&msg);
                     return Err(msg);
                 }
                 write_log(&format!("ISO: {} (exists)", iso));
                 cmd.arg("-cdrom").arg(iso);
                 cmd.arg("-boot").arg("d");
             }
        }

        write_log(&format!("Launching QEMU: VNC :{} (port {}), KVM: {}", vnc_num, vnc_port, kvm_available));
        info!("Starting VM {}: qemu-system-x86_64 (KVM: {}, VNC :{})", 
              name, kvm_available, vnc_num);

        // Redirect QEMU stderr to log file (append mode, don't overwrite diagnostics)
        if let Ok(log_file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            cmd.stderr(std::process::Stdio::from(log_file));
        }

        let output = cmd.output().map_err(|e| {
            let msg = format!("Failed to execute QEMU: {}", e);
            write_log(&msg); msg
        })?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let log_content = fs::read_to_string(&log_path).unwrap_or_default();
            let err_msg = if !stderr.is_empty() { stderr } else { log_content.clone() };
            write_log(&format!("QEMU exit with error: {}", err_msg));
            error!("QEMU failed for VM {}: {}", name, err_msg);
            
            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
            }
            return Err(format!("QEMU failed to start: {}", err_msg));
        }

        // -daemonize makes QEMU fork, so output.status may be 0 even if the child crashes.
        std::thread::sleep(std::time::Duration::from_secs(1));
        
        if !self.check_running(name) {
            let log_content = fs::read_to_string(&log_path).unwrap_or_else(|_| "no log available".to_string());
            write_log("VM exited immediately after daemonize — check QEMU errors above");
            error!("VM {} exited immediately after daemonize. Log: {}", name, log_content);
            
            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
            }
            return Err(format!("VM crashed immediately after starting. QEMU log:\n{}", log_content));
        }

        write_log(&format!("VM started successfully. VNC :{} (port {}), noVNC WS :{}", vnc_num, vnc_port, ws_port));

        // Save runtime port info so frontend can connect
        let runtime = serde_json::json!({
            "vnc_port": vnc_port,
            "vnc_ws_port": ws_port,
            "vnc_display": vnc_num,
            "kvm": kvm_available,
        });
        let runtime_path = self.base_dir.join(format!("{}.runtime.json", name));
        let _ = fs::write(&runtime_path, runtime.to_string());
        
        info!("Started VM {} on VNC :{} (port {}), noVNC WS :{}", name, vnc_num, vnc_port, ws_port);
        Ok(())
    }

    /// Create and configure a TAP interface
    fn setup_tap(&self, tap: &str) -> Result<(), String> {
        // Create TAP device
        let output = Command::new("ip")
            .args(["tuntap", "add", "dev", tap, "mode", "tap"])
            .output()
            .map_err(|e| format!("Failed to create TAP {}: {}", tap, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "already exists"
            if !stderr.contains("EEXIST") && !stderr.contains("File exists") {
                return Err(format!("TAP creation failed: {}", stderr));
            }
        }

        // Bring TAP up
        let output = Command::new("ip")
            .args(["link", "set", tap, "up"])
            .output()
            .map_err(|e| format!("Failed to bring up TAP {}: {}", tap, e))?;

        if !output.status.success() {
            return Err(format!("TAP up failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        info!("TAP interface {} created and up", tap);
        Ok(())
    }

    /// Set up host-side routing and forwarding for WolfNet IP through a TAP
    fn setup_wolfnet_routing(&self, tap: &str, wolfnet_ip: &str) -> Result<(), String> {
        // Enable IP forwarding
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.proxy_arp=1", tap)]).output();

        // Add route: wolfnet_ip/32 via TAP
        let _ = Command::new("ip").args(["route", "del", &format!("{}/32", wolfnet_ip)]).output();
        let route_result = Command::new("ip")
            .args(["route", "add", &format!("{}/32", wolfnet_ip), "dev", tap])
            .output()
            .map_err(|e| format!("Route add failed: {}", e))?;

        if !route_result.status.success() {
            let err = String::from_utf8_lossy(&route_result.stderr);
            if !err.contains("File exists") {
                info!("Route add note: {}", err.trim());
            }
        }

        // iptables FORWARD rules between wolfnet0 and TAP (idempotent)
        let check = Command::new("iptables")
            .args(["-C", "FORWARD", "-i", "wolfnet0", "-o", tap, "-j", "ACCEPT"]).output();
        if check.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables")
                .args(["-A", "FORWARD", "-i", "wolfnet0", "-o", tap, "-j", "ACCEPT"]).output();
            let _ = Command::new("iptables")
                .args(["-A", "FORWARD", "-i", tap, "-o", "wolfnet0", "-j", "ACCEPT"]).output();
        }

        // Also allow TAP to reach the outside (masquerade)
        let check_nat = Command::new("iptables")
            .args(["-t", "nat", "-C", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "-j", "MASQUERADE"]).output();
        if check_nat.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables")
                .args(["-t", "nat", "-A", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "-j", "MASQUERADE"]).output();
        }

        info!("WolfNet routing set up for {} via {}", wolfnet_ip, tap);
        Ok(())
    }

    /// Clean up TAP interface and routes
    fn cleanup_tap(&self, tap: &str) -> Result<(), String> {
        let _ = Command::new("ip").args(["link", "set", tap, "down"]).output();
        let _ = Command::new("ip").args(["tuntap", "del", "dev", tap, "mode", "tap"]).output();
        // Clean up iptables rules
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", "wolfnet0", "-o", tap, "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", tap, "-o", "wolfnet0", "-j", "ACCEPT"]).output();
        info!("Cleaned up TAP interface {}", tap);
        Ok(())
    }

    /// Clean up WolfNet routes for a specific IP
    fn cleanup_wolfnet_routes(&self, wolfnet_ip: &str) {
        let _ = Command::new("ip").args(["route", "del", &format!("{}/32", wolfnet_ip)]).output();
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "-j", "MASQUERADE"]).output();
    }

    pub fn stop_vm(&self, name: &str) -> Result<(), String> {
        // Read config to get WolfNet IP for cleanup
        let config = self.get_vm(name);

        let output = Command::new("pkill")
            .arg("-f")
            .arg(format!("qemu-system-x86_64.*-name {}", name))
            .output()
            .map_err(|e| e.to_string())?;
            
        if !output.status.success() {
            return Err("Failed to stop VM (process not found?)".to_string());
        }

        // Clean up networking
        if let Some(config) = config {
            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
                if let Some(ref ip) = config.wolfnet_ip {
                    self.cleanup_wolfnet_routes(ip);
                }
            }
        }

        // Clean up runtime file
        let _ = fs::remove_file(self.base_dir.join(format!("{}.runtime.json", name)));

        info!("Stopped VM: {}", name);
        Ok(())
    }

    pub fn get_vm(&self, name: &str) -> Option<VmConfig> {
        let config_path = self.vm_config_path(name);
        let content = fs::read_to_string(&config_path).ok()?;
        let mut vm: VmConfig = serde_json::from_str(&content).ok()?;
        vm.running = self.check_running(name);
        if vm.running {
            vm.vnc_port = self.read_runtime_vnc_port(name);
            vm.vnc_ws_port = self.read_runtime_ws_port(name);
        }
        Some(vm)
    }

    pub fn delete_vm(&self, name: &str) -> Result<(), String> {
        if self.check_running(name) {
            let _ = self.stop_vm(name);
        }

        let _ = fs::remove_file(self.vm_config_path(name));
        let _ = fs::remove_file(self.vm_disk_path(name));
        let _ = fs::remove_file(self.base_dir.join(format!("{}.runtime.json", name)));
        let _ = fs::remove_file(self.base_dir.join(format!("{}.log", name)));
        
        info!("Deleted VM: {}", name);
        Ok(())
    }

    fn check_running(&self, name: &str) -> bool {
        let output = Command::new("pgrep")
            .arg("-f")
            .arg(format!("qemu-system-x86_64.*-name {}", name))
            .output();
        match output {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    /// Read the VNC port from runtime file
    fn read_runtime_vnc_port(&self, name: &str) -> Option<u16> {
        let runtime_path = self.base_dir.join(format!("{}.runtime.json", name));
        let content = fs::read_to_string(&runtime_path).ok()?;
        let runtime: serde_json::Value = serde_json::from_str(&content).ok()?;
        runtime.get("vnc_port").and_then(|v| v.as_u64()).map(|v| v as u16)
    }

    /// Read the WebSocket port from runtime file (for noVNC)
    fn read_runtime_ws_port(&self, name: &str) -> Option<u16> {
        let runtime_path = self.base_dir.join(format!("{}.runtime.json", name));
        let content = fs::read_to_string(&runtime_path).ok()?;
        let runtime: serde_json::Value = serde_json::from_str(&content).ok()?;
        runtime.get("vnc_ws_port").and_then(|v| v.as_u64()).map(|v| v as u16)
    }
}
