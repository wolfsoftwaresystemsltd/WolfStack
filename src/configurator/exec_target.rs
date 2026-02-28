// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! ExecTarget — abstraction for executing configurator operations on the host,
//! inside Docker containers, or inside LXC containers.

use std::io::Write;
use std::process::{Command, Stdio};
use crate::installer::DistroFamily;

/// Where a configurator command should execute
#[derive(Debug, Clone)]
pub enum ExecTarget {
    /// Execute on the local host (default, backward-compatible)
    Host,
    /// Execute inside a Docker container
    Docker(String),
    /// Execute inside an LXC container
    Lxc(String),
}

impl Default for ExecTarget {
    fn default() -> Self { ExecTarget::Host }
}

impl ExecTarget {
    /// Execute a shell command and return (stdout, stderr, success)
    pub fn exec_full(&self, cmd: &str) -> Result<(String, String, bool), String> {
        let output = match self {
            ExecTarget::Host => {
                Command::new("sudo")
                    .args(["sh", "-c", cmd])
                    .output()
                    .map_err(|e| format!("Failed to execute command: {}", e))?
            }
            ExecTarget::Docker(name) => {
                Command::new("docker")
                    .args(["exec", name, "sh", "-c", cmd])
                    .output()
                    .map_err(|e| format!("Failed to exec in container '{}': {}", name, e))?
            }
            ExecTarget::Lxc(name) => {
                Command::new("lxc-attach")
                    .args(["-n", name, "--", "sh", "-c", cmd])
                    .output()
                    .map_err(|e| format!("Failed to attach to container '{}': {}", name, e))?
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok((stdout, stderr, output.status.success()))
    }

    /// Execute a shell command and return stdout on success, stderr on failure
    pub fn exec(&self, cmd: &str) -> Result<String, String> {
        let (stdout, stderr, success) = self.exec_full(cmd)?;
        if success {
            Ok(stdout)
        } else {
            Err(if stderr.is_empty() { stdout } else { stderr })
        }
    }

    /// Read a file and return its contents
    pub fn read_file(&self, path: &str) -> Result<String, String> {
        match self {
            ExecTarget::Host => {
                std::fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read {}: {}", path, e))
            }
            _ => {
                self.exec(&format!("cat '{}'", path.replace('\'', "'\\''")))
            }
        }
    }

    /// Write content to a file
    pub fn write_file(&self, path: &str, content: &str) -> Result<(), String> {
        match self {
            ExecTarget::Host => {
                let mut child = Command::new("sudo")
                    .args(["tee", path])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("Failed to write {}: {}", path, e))?;

                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(content.as_bytes())
                        .map_err(|e| format!("Failed to write content: {}", e))?;
                }

                let output = child.wait_with_output()
                    .map_err(|e| format!("Failed to wait for write: {}", e))?;

                if output.status.success() {
                    Ok(())
                } else {
                    Err(String::from_utf8_lossy(&output.stderr).to_string())
                }
            }
            ExecTarget::Docker(name) => {
                let escaped_path = path.replace('\'', "'\\''");
                let mut child = Command::new("docker")
                    .args(["exec", "-i", name, "sh", "-c", &format!("cat > '{}'", escaped_path)])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("Failed to write in container '{}': {}", name, e))?;

                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(content.as_bytes())
                        .map_err(|e| format!("Failed to write content: {}", e))?;
                }

                let output = child.wait_with_output()
                    .map_err(|e| format!("Failed to wait for write: {}", e))?;

                if output.status.success() {
                    Ok(())
                } else {
                    Err(String::from_utf8_lossy(&output.stderr).to_string())
                }
            }
            ExecTarget::Lxc(name) => {
                let escaped_path = path.replace('\'', "'\\''");
                let mut child = Command::new("lxc-attach")
                    .args(["-n", name, "--", "sh", "-c", &format!("cat > '{}'", escaped_path)])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("Failed to write in container '{}': {}", name, e))?;

                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(content.as_bytes())
                        .map_err(|e| format!("Failed to write content: {}", e))?;
                }

                let output = child.wait_with_output()
                    .map_err(|e| format!("Failed to wait for write: {}", e))?;

                if output.status.success() {
                    Ok(())
                } else {
                    Err(String::from_utf8_lossy(&output.stderr).to_string())
                }
            }
        }
    }

    /// List entries in a directory (returns file/dir names, not full paths)
    pub fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
        match self {
            ExecTarget::Host => {
                let entries = std::fs::read_dir(path)
                    .map_err(|e| format!("Failed to read directory {}: {}", path, e))?;

                let mut names: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                names.sort();
                Ok(names)
            }
            _ => {
                let output = self.exec(&format!("ls -1 '{}' 2>/dev/null", path.replace('\'', "'\\''")))?;
                Ok(output.lines()
                    .filter(|l| !l.is_empty())
                    .map(|l| l.to_string())
                    .collect())
            }
        }
    }

    /// Check if a path exists
    pub fn path_exists(&self, path: &str) -> Result<bool, String> {
        match self {
            ExecTarget::Host => Ok(std::path::Path::new(path).exists()),
            _ => {
                let (_, _, success) = self.exec_full(&format!("test -e '{}'", path.replace('\'', "'\\''")))?;
                Ok(success)
            }
        }
    }

    /// Check if a path is a symbolic link
    pub fn is_symlink(&self, path: &str) -> Result<bool, String> {
        match self {
            ExecTarget::Host => Ok(std::path::Path::new(path).is_symlink()),
            _ => {
                let (_, _, success) = self.exec_full(&format!("test -L '{}'", path.replace('\'', "'\\''")))?;
                Ok(success)
            }
        }
    }

    /// Create a symbolic link (ln -sf src dst)
    pub fn symlink(&self, src: &str, dst: &str) -> Result<(), String> {
        let cmd = format!("ln -sf '{}' '{}'",
            src.replace('\'', "'\\''"),
            dst.replace('\'', "'\\''"));
        match self {
            ExecTarget::Host => {
                let output = Command::new("sudo")
                    .args(["sh", "-c", &cmd])
                    .output()
                    .map_err(|e| format!("Failed to create symlink: {}", e))?;
                if output.status.success() { Ok(()) }
                else { Err(String::from_utf8_lossy(&output.stderr).to_string()) }
            }
            _ => { self.exec(&cmd)?; Ok(()) }
        }
    }

    /// Remove a file
    pub fn remove_file(&self, path: &str) -> Result<(), String> {
        let cmd = format!("rm -f '{}'", path.replace('\'', "'\\''"));
        match self {
            ExecTarget::Host => {
                let output = Command::new("sudo")
                    .args(["sh", "-c", &cmd])
                    .output()
                    .map_err(|e| format!("Failed to remove file: {}", e))?;
                if output.status.success() { Ok(()) }
                else { Err(String::from_utf8_lossy(&output.stderr).to_string()) }
            }
            _ => { self.exec(&cmd)?; Ok(()) }
        }
    }

    /// Detect the Linux distribution family (on host or inside container)
    pub fn detect_distro(&self) -> DistroFamily {
        match self {
            ExecTarget::Host => crate::installer::detect_distro(),
            _ => {
                if self.path_exists("/etc/debian_version").unwrap_or(false) {
                    DistroFamily::Debian
                } else if self.path_exists("/etc/redhat-release").unwrap_or(false)
                    || self.path_exists("/etc/fedora-release").unwrap_or(false)
                {
                    DistroFamily::RedHat
                } else if self.path_exists("/etc/SuSE-release").unwrap_or(false)
                    || self.path_exists("/etc/SUSE-brand").unwrap_or(false)
                    || self.path_exists("/usr/bin/zypper").unwrap_or(false)
                {
                    DistroFamily::Suse
                } else {
                    DistroFamily::Unknown
                }
            }
        }
    }
}
