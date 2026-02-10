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
                             // If running, try to find VNC port (can scrape from process args or store somewhere transient)
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
        // Find process and parse args
        // pgrep -a -f "name {name}"
         let output = Command::new("pgrep")
            .arg("-a")
            .arg("-f")
            .arg(format!("qemu-system-x86_64.*-name {}", name))
            .output().ok()?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains(&format!("-name {}", name)) {
                // Parse -vnc :X
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

    pub fn create_vm(&self, mut config: VmConfig) -> Result<(), String> {
        if self.vm_config_path(&config.name).exists() {
            return Err("VM already exists".to_string());
        }

        // Validation
        if config.cpus == 0 { config.cpus = 1; }
        if config.memory_mb == 0 { config.memory_mb = 1024; }
        if config.disk_size_gb == 0 { config.disk_size_gb = 10; }

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
        
        info!("Created VM: {}", config.name);
        Ok(())
    }

    pub fn start_vm(&self, name: &str) -> Result<(), String> {
        if self.check_running(name) {
             return Err("VM already running".to_string());
        }

        let config_path = self.vm_config_path(name);
        let content = fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
        let config: VmConfig = serde_json::from_str(&content).map_err(|e| e.to_string())?;

        // Simple random port for now to avoid collision in basic usage
        // In prod, check `ss -lnt`
        let mut rng = rand::thread_rng();
        let vnc_num = rng.gen_range(10..99); 

        let vnc_arg = format!(":{}", vnc_num);
        
        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.arg("-name").arg(name)
           .arg("-m").arg(format!("{}M", config.memory_mb))
           .arg("-smp").arg(format!("{}", config.cpus))
           .arg("-enable-kvm") 
           .arg("-cpu").arg("host") // Best performance
           .arg("-drive").arg(format!("file={},format=qcow2,if=virtio", self.vm_disk_path(name).display()))
           .arg("-vnc").arg(&vnc_arg)
           .arg("-net").arg("nic,model=virtio")
           .arg("-net").arg("user") // User networking
           .arg("-daemonize"); 

        if let Some(iso) = &config.iso_path {
             if !iso.is_empty() {
                 cmd.arg("-cdrom").arg(iso);
                 cmd.arg("-boot").arg("d"); // Boot from CDROM
             }
        }

        let output = cmd.output().map_err(|e| e.to_string())?;
        if !output.status.success() {
             return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }
        
        info!("Started VM {} on VNC display {}", name, vnc_num);
        Ok(())
    }

    pub fn stop_vm(&self, name: &str) -> Result<(), String> {
        // Graceful shutdown not implemented via QMP yet, so we kill
        // TODO: Implement QMP for safe shutdown
        let output = Command::new("pkill")
            .arg("-f")
            .arg(format!("qemu-system-x86_64.*-name {}", name))
            .output()
            .map_err(|e| e.to_string())?;
            
        if !output.status.success() {
            return Err("Failed to stop VM (process not found?)".to_string());
        }
        
        Ok(())
    }

    pub fn delete_vm(&self, name: &str) -> Result<(), String> {
        if self.check_running(name) {
            let _ = self.stop_vm(name);
        }

        let _ = fs::remove_file(self.vm_config_path(name));
        let _ = fs::remove_file(self.vm_disk_path(name));
        
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
