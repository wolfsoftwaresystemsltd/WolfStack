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
    base_dir: PathBuf,
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
                                 vm.vnc_port = self.find_vnc_port(&vm.name); 
                             } else {
                                 vm.vnc_port = None;
                             }
                             vms.push(vm);
                         }
                     }
                 }
            }
        }
        vms
    }

    pub fn find_vnc_port(&self, name: &str) -> Option<u16> {
         let output = Command::new("pgrep")
            .arg("-a")
            .arg("-f")
            .arg(format!("qemu-system-x86_64.*-name {}", name))
            .output().ok()?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains(&format!("-name {}", name)) {
                if let Some(pos) = line.find("-vnc :") {
                    let rest = &line[pos + 6..];
                    let end = rest.find(' ').unwrap_or(rest.len());
                    if let Ok(display) = rest[..end].parse::<u16>() {
                        return Some(5900 + display);
                    }
                }
            }
        }
        None
    }

    fn vm_config_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", name))
    }
    
    fn vm_disk_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.qcow2", name))
    }

    /// Path to the QEMU monitor socket (for serial console)
    pub fn vm_serial_socket(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.serial.sock", name))
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

    pub fn start_vm(&self, name: &str) -> Result<(), String> {
        if self.check_running(name) {
             return Err("VM already running".to_string());
        }

        let config_path = self.vm_config_path(name);
        let content = fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
        let config: VmConfig = serde_json::from_str(&content).map_err(|e| e.to_string())?;

        let mut rng = rand::thread_rng();
        let vnc_num = rng.gen_range(10..99); 
        let vnc_arg = format!(":{}", vnc_num);
        
        let serial_sock = self.vm_serial_socket(name);
        // Remove stale socket
        let _ = fs::remove_file(&serial_sock);

        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.arg("-name").arg(name)
           .arg("-m").arg(format!("{}M", config.memory_mb))
           .arg("-smp").arg(format!("{}", config.cpus))
           .arg("-enable-kvm") 
           .arg("-cpu").arg("host")
           .arg("-drive").arg(format!("file={},format=qcow2,if=virtio", self.vm_disk_path(name).display()))
           .arg("-vnc").arg(&vnc_arg)
           // Serial console via UNIX socket for web terminal
           .arg("-serial").arg(format!("unix:{},server,nowait", serial_sock.display()))
           .arg("-daemonize");

        // Networking: TAP with WolfNet IP, or user-mode fallback
        if let Some(ref wolfnet_ip) = config.wolfnet_ip {
            let tap = Self::tap_name(name);
            
            // Create TAP interface
            self.setup_tap(&tap)?;
            
            cmd.arg("-netdev").arg(format!("tap,id=net0,ifname={},script=no,downscript=no", tap))
               .arg("-device").arg("virtio-net-pci,netdev=net0");

            // Set up host-side routing for the WolfNet IP
            self.setup_wolfnet_routing(&tap, wolfnet_ip)?;

            info!("VM {} using TAP {} with WolfNet IP {}", name, tap, wolfnet_ip);
        } else {
            cmd.arg("-net").arg("nic,model=virtio")
               .arg("-net").arg("user");
        }

        if let Some(iso) = &config.iso_path {
             if !iso.is_empty() {
                 cmd.arg("-cdrom").arg(iso);
                 cmd.arg("-boot").arg("d");
             }
        }

        let output = cmd.output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            // Clean up TAP on failure
            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
            }
            return Err(stderr);
        }
        
        info!("Started VM {} on VNC display {} (port {})", name, vnc_num, 5900 + vnc_num);
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

        // Clean up serial socket
        let _ = fs::remove_file(self.vm_serial_socket(name));

        info!("Stopped VM: {}", name);
        Ok(())
    }

    pub fn get_vm(&self, name: &str) -> Option<VmConfig> {
        let config_path = self.vm_config_path(name);
        let content = fs::read_to_string(&config_path).ok()?;
        let mut vm: VmConfig = serde_json::from_str(&content).ok()?;
        vm.running = self.check_running(name);
        if vm.running {
            vm.vnc_port = self.find_vnc_port(name);
        }
        Some(vm)
    }

    pub fn delete_vm(&self, name: &str) -> Result<(), String> {
        if self.check_running(name) {
            let _ = self.stop_vm(name);
        }

        let _ = fs::remove_file(self.vm_config_path(name));
        let _ = fs::remove_file(self.vm_disk_path(name));
        let _ = fs::remove_file(self.vm_serial_socket(name));
        
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
}
