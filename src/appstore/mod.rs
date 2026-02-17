// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! App Store — browse and install popular applications with one click
//!
//! Supports three deployment targets:
//! - Docker containers (pull image, create container with preconfigured settings)
//! - LXC containers (create from template, run setup commands)
//! - Bare metal (install packages directly on the host)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

// ─── Manifest types ───

/// How to install an app via Docker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerTarget {
    pub image: String,
    pub ports: Vec<String>,
    pub env: Vec<String>,
    pub volumes: Vec<String>,
    /// Optional secondary containers (e.g. a database)
    #[serde(default)]
    pub sidecars: Vec<DockerSidecar>,
}

/// A secondary container bundled with the main app
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSidecar {
    pub name_suffix: String,
    pub image: String,
    pub ports: Vec<String>,
    pub env: Vec<String>,
    pub volumes: Vec<String>,
}

/// How to install an app in an LXC container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LxcTarget {
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    /// Commands to run inside the container after creation
    pub setup_commands: Vec<String>,
}

/// How to install an app directly on the host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BareMetalTarget {
    /// Debian/Ubuntu packages
    pub packages_debian: Vec<String>,
    /// RHEL/Fedora packages
    pub packages_redhat: Vec<String>,
    /// Optional post-install commands
    pub post_install: Vec<String>,
    /// Systemd service name to enable/start
    pub service: Option<String>,
}

/// A user-facing input field shown in the install wizard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInput {
    pub id: String,
    pub label: String,
    pub input_type: String, // "text", "password", "number", "select"
    pub default: Option<String>,
    pub required: bool,
    pub placeholder: Option<String>,
    /// For select type
    #[serde(default)]
    pub options: Vec<String>,
}

/// Full app manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    pub id: String,
    pub name: String,
    pub icon: String,         // emoji or SVG icon name
    pub category: String,
    pub description: String,
    pub website: Option<String>,
    pub docker: Option<DockerTarget>,
    pub lxc: Option<LxcTarget>,
    pub bare_metal: Option<BareMetalTarget>,
    #[serde(default)]
    pub user_inputs: Vec<UserInput>,
}

/// Tracking record of an installed app
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub install_id: String,
    pub app_id: String,
    pub app_name: String,
    pub target: String,           // "docker", "lxc", "bare"
    pub container_name: Option<String>,
    pub installed_at: String,
    /// Any sidecar container names
    #[serde(default)]
    pub sidecar_names: Vec<String>,
}

// ─── Installed apps persistence ───

const INSTALLED_FILE: &str = "/etc/wolfstack/appstore/installed.json";

fn load_installed() -> Vec<InstalledApp> {
    std::fs::read_to_string(INSTALLED_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_installed(apps: &[InstalledApp]) {
    let _ = std::fs::create_dir_all("/etc/wolfstack/appstore");
    let _ = std::fs::write(INSTALLED_FILE, serde_json::to_string_pretty(apps).unwrap_or_default());
}

// ─── Public API ───

/// List all available apps, optionally filtered by query and/or category
pub fn list_apps(query: Option<&str>, category: Option<&str>) -> Vec<AppManifest> {
    let catalogue = built_in_catalogue();
    catalogue.into_iter().filter(|app| {
        let q_match = query.map_or(true, |q| {
            let q = q.to_lowercase();
            app.name.to_lowercase().contains(&q) ||
            app.description.to_lowercase().contains(&q) ||
            app.id.to_lowercase().contains(&q)
        });
        let c_match = category.map_or(true, |c| {
            c.eq_ignore_ascii_case("all") || app.category.eq_ignore_ascii_case(c)
        });
        q_match && c_match
    }).collect()
}

/// Get a single app by ID
pub fn get_app(id: &str) -> Option<AppManifest> {
    built_in_catalogue().into_iter().find(|a| a.id == id)
}

/// List installed apps
pub fn list_installed_apps() -> Vec<InstalledApp> {
    load_installed()
}

/// Install an app
pub fn install_app(
    app_id: &str,
    target: &str,
    container_name: &str,
    user_inputs: &HashMap<String, String>,
) -> Result<String, String> {
    let app = get_app(app_id).ok_or_else(|| format!("App '{}' not found", app_id))?;
    info!("📦 App Store: installing {} via {} as '{}'", app.name, target, container_name);

    let mut sidecar_names: Vec<String> = Vec::new();

    let result = match target {
        "docker" => install_docker(&app, container_name, user_inputs, &mut sidecar_names),
        "lxc" => install_lxc(&app, container_name, user_inputs),
        "bare" => install_bare_metal(&app, user_inputs),
        _ => Err(format!("Unknown install target: {}", target)),
    }?;

    // Track the installation
    let install_id = format!("{}_{}", app_id, chrono_timestamp());
    let mut installed = load_installed();
    installed.push(InstalledApp {
        install_id: install_id.clone(),
        app_id: app_id.to_string(),
        app_name: app.name.clone(),
        target: target.to_string(),
        container_name: Some(container_name.to_string()),
        installed_at: chrono_timestamp(),
        sidecar_names,
    });
    save_installed(&installed);

    info!("✅ App Store: {} installed successfully ({})", app.name, install_id);
    Ok(result)
}

/// Uninstall an app by its install ID
pub fn uninstall_app(install_id: &str) -> Result<String, String> {
    let mut installed = load_installed();
    let idx = installed.iter().position(|a| a.install_id == install_id)
        .ok_or_else(|| format!("Install ID '{}' not found", install_id))?;

    let app = installed.remove(idx);
    info!("🗑️ App Store: uninstalling {} ({})", app.app_name, app.target);

    // Remove the container/packages
    match app.target.as_str() {
        "docker" => {
            if let Some(ref name) = app.container_name {
                let _ = crate::containers::docker_stop(name);
                let _ = crate::containers::docker_remove(name);
            }
            // Remove sidecars
            for sidecar in &app.sidecar_names {
                let _ = crate::containers::docker_stop(sidecar);
                let _ = crate::containers::docker_remove(sidecar);
            }
        }
        "lxc" => {
            if let Some(ref name) = app.container_name {
                let _ = crate::containers::lxc_stop(name);
                let _ = crate::containers::lxc_destroy(name);
            }
        }
        "bare" => {
            // We don't auto-remove packages for safety
            return Err("Bare metal apps must be manually uninstalled".to_string());
        }
        _ => {}
    }

    save_installed(&installed);
    Ok(format!("{} has been uninstalled", app.app_name))
}

// ─── Install implementations ───

fn install_docker(
    app: &AppManifest,
    container_name: &str,
    user_inputs: &HashMap<String, String>,
    sidecar_names: &mut Vec<String>,
) -> Result<String, String> {
    let docker = app.docker.as_ref()
        .ok_or("This app doesn't support Docker installation")?;

    // Auto-allocate a WolfNet IP for this container
    let wolfnet_ip = crate::containers::next_available_wolfnet_ip();
    if let Some(ref ip) = wolfnet_ip {
        info!("📦 App Store: allocated WolfNet IP {} for {}", ip, container_name);
    }

    // Install sidecars first (e.g. database)
    for sidecar in &docker.sidecars {
        let sidecar_name = format!("{}-{}", container_name, sidecar.name_suffix);
        let env = substitute_inputs(&sidecar.env, user_inputs);

        info!("📦 App Store: pulling sidecar image {}", sidecar.image);
        crate::containers::docker_pull(&sidecar.image)?;

        info!("📦 App Store: creating sidecar container {}", sidecar_name);
        crate::containers::docker_create(
            &sidecar_name,
            &sidecar.image,
            &sidecar.ports,
            &env,
            None,  // no WolfNet IP for sidecars
            None,  // no memory limit
            None,  // no CPU limit
            None,  // no storage limit
            &sidecar.volumes,
        )?;
        // Don't start sidecars — user will start everything manually
        sidecar_names.push(sidecar_name);
    }

    // Pull the main image
    info!("📦 App Store: pulling image {}", docker.image);
    crate::containers::docker_pull(&docker.image)?;

    // Substitute user inputs into env vars
    let env = substitute_inputs(&docker.env, user_inputs);

    // Create the container (not started)
    info!("📦 App Store: creating container {}", container_name);
    crate::containers::docker_create(
        container_name,
        &docker.image,
        &docker.ports,
        &env,
        wolfnet_ip.as_deref(),
        None,
        None,
        None,
        &docker.volumes,
    )?;

    let mut msg = format!("{} configured as Docker container '{}' (stopped)", app.name, container_name);
    if let Some(ref ip) = wolfnet_ip {
        msg.push_str(&format!(" — WolfNet IP: {}", ip));
    }
    if !sidecar_names.is_empty() {
        msg.push_str(&format!(" (with sidecars: {})", sidecar_names.join(", ")));
    }
    Ok(msg)
}

fn install_lxc(
    app: &AppManifest,
    container_name: &str,
    user_inputs: &HashMap<String, String>,
) -> Result<String, String> {
    let lxc = app.lxc.as_ref()
        .ok_or("This app doesn't support LXC installation")?;

    // Auto-allocate a WolfNet IP
    let wolfnet_ip = crate::containers::next_available_wolfnet_ip();
    if let Some(ref ip) = wolfnet_ip {
        info!("📦 App Store: allocated WolfNet IP {} for LXC {}", ip, container_name);
    }

    // Create the container
    info!("📦 App Store: creating LXC container {}", container_name);
    crate::containers::lxc_create(
        container_name,
        &lxc.distribution,
        &lxc.release,
        &lxc.architecture,
        None, // default storage
    )?;

    // Write WolfNet IP file so it's pre-assigned
    if let Some(ref ip) = wolfnet_ip {
        let wolfnet_dir = format!("/var/lib/lxc/{}/.wolfnet", container_name);
        let _ = std::fs::create_dir_all(&wolfnet_dir);
        let _ = std::fs::write(format!("{}/ip", wolfnet_dir), ip);
    }

    // Start the container temporarily to run setup commands
    info!("📦 App Store: starting container to run setup...");
    crate::containers::lxc_start(container_name)?;

    // Wait for the container to boot
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Run setup commands inside the container
    let commands = substitute_inputs(&lxc.setup_commands, user_inputs);
    for cmd in &commands {
        info!("📦 App Store: running in container: {}", cmd);
        let output = std::process::Command::new("lxc-attach")
            .args(["-n", container_name, "--", "sh", "-c", cmd])
            .output()
            .map_err(|e| format!("Failed to run setup command: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            info!("⚠️ App Store: command exited with {}: {}", output.status, stderr);
        }
    }

    // Stop the container — it's configured but not running
    info!("📦 App Store: setup complete, stopping container");
    let _ = crate::containers::lxc_stop(container_name);

    let mut msg = format!("{} configured as LXC container '{}' (stopped)", app.name, container_name);
    if let Some(ref ip) = wolfnet_ip {
        msg.push_str(&format!(" — WolfNet IP: {}", ip));
    }
    msg.push_str(". Start the container when ready.");
    Ok(msg)
}

fn install_bare_metal(
    app: &AppManifest,
    user_inputs: &HashMap<String, String>,
) -> Result<String, String> {
    let bare = app.bare_metal.as_ref()
        .ok_or("This app doesn't support bare metal installation")?;

    // Detect distro inline (installer::pkg_install_cmd is private)
    let is_debian = std::path::Path::new("/etc/debian_version").exists();
    let is_redhat = std::path::Path::new("/etc/redhat-release").exists()
        || std::path::Path::new("/etc/fedora-release").exists();

    let (pkg_cmd, install_flag) = if is_debian {
        ("apt-get", "install")
    } else if is_redhat {
        ("dnf", "install")
    } else {
        ("apt-get", "install") // fallback
    };

    let packages = if is_debian {
        &bare.packages_debian
    } else if is_redhat {
        &bare.packages_redhat
    } else {
        &bare.packages_debian // fallback
    };

    if !packages.is_empty() {
        info!("📦 App Store: installing packages: {}", packages.join(", "));
        let output = std::process::Command::new(pkg_cmd)
            .arg(install_flag)
            .arg("-y")
            .args(packages)
            .output()
            .map_err(|e| format!("Package install failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Package install failed: {}", stderr));
        }
    }

    // Run post-install commands
    let commands = substitute_inputs(&bare.post_install, user_inputs);
    for cmd in &commands {
        info!("📦 App Store: running post-install: {}", cmd);
        let output = std::process::Command::new("sh")
            .args(["-c", cmd])
            .output()
            .map_err(|e| format!("Post-install command failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            info!("⚠️ App Store: post-install exited with {}: {}", output.status, stderr);
        }
    }

    // Enable and start the service
    if let Some(ref service) = bare.service {
        let _ = std::process::Command::new("systemctl")
            .args(["enable", "--now", service])
            .output();
    }

    Ok(format!("{} installed on host", app.name))
}

// ─── Helpers ───

/// Replace ${VAR} placeholders with user input values
fn substitute_inputs(templates: &[String], inputs: &HashMap<String, String>) -> Vec<String> {
    templates.iter().map(|t| {
        let mut result = t.clone();
        for (key, value) in inputs {
            result = result.replace(&format!("${{{}}}", key), value);
        }
        result
    }).collect()
}

/// Simple timestamp for IDs
fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{}", secs)
}

// ─── Built-in Catalogue ───

pub fn built_in_catalogue() -> Vec<AppManifest> {
    vec![
        // ── Web ──
        AppManifest {
            id: "wordpress".into(),
            name: "WordPress".into(),
            icon: "🌐".into(),
            category: "Web".into(),
            description: "The world's most popular CMS for blogs and websites".into(),
            website: Some("https://wordpress.org".into()),
            docker: Some(DockerTarget {
                image: "wordpress:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec![
                    "WORDPRESS_DB_HOST=${CONTAINER_NAME}-db".into(),
                    "WORDPRESS_DB_USER=wordpress".into(),
                    "WORDPRESS_DB_PASSWORD=${DB_PASSWORD}".into(),
                    "WORDPRESS_DB_NAME=wordpress".into(),
                ],
                volumes: vec!["wordpress_data:/var/www/html".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mariadb:11".into(),
                    ports: vec![],
                    env: vec![
                        "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                        "MYSQL_DATABASE=wordpress".into(),
                        "MYSQL_USER=wordpress".into(),
                        "MYSQL_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["wordpress_db:/var/lib/mysql".into()],
                }],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y apache2 php php-mysql php-gd php-xml php-mbstring mariadb-server curl".into(),
                    "systemctl start mariadb".into(),
                    "mysql -e \"CREATE DATABASE wordpress; CREATE USER 'wordpress'@'localhost' IDENTIFIED BY '${DB_PASSWORD}'; GRANT ALL ON wordpress.* TO 'wordpress'@'localhost'; FLUSH PRIVILEGES;\"".into(),
                    "cd /var/www/html && curl -sL https://wordpress.org/latest.tar.gz | tar xz --strip-components=1".into(),
                    "chown -R www-data:www-data /var/www/html".into(),
                    "systemctl enable apache2 mariadb".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["apache2".into(), "php".into(), "php-mysql".into(), "php-gd".into(), "php-xml".into(), "php-mbstring".into(), "mariadb-server".into()],
                packages_redhat: vec!["httpd".into(), "php".into(), "php-mysqlnd".into(), "php-gd".into(), "php-xml".into(), "php-mbstring".into(), "mariadb-server".into()],
                post_install: vec![
                    "systemctl enable --now mariadb".into(),
                    "cd /var/www/html && curl -sL https://wordpress.org/latest.tar.gz | tar xz --strip-components=1 && chown -R www-data:www-data /var/www/html".into(),
                ],
                service: Some("apache2".into()),
            }),
            user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Strong password for the database".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "nextcloud".into(),
            name: "Nextcloud".into(),
            icon: "☁️".into(),
            category: "Web".into(),
            description: "Self-hosted cloud storage, file sync, and collaboration platform".into(),
            website: Some("https://nextcloud.com".into()),
            docker: Some(DockerTarget {
                image: "nextcloud:latest".into(),
                ports: vec!["8081:80".into()],
                env: vec![
                    "MYSQL_HOST=${CONTAINER_NAME}-db".into(),
                    "MYSQL_DATABASE=nextcloud".into(),
                    "MYSQL_USER=nextcloud".into(),
                    "MYSQL_PASSWORD=${DB_PASSWORD}".into(),
                    "NEXTCLOUD_ADMIN_USER=${ADMIN_USER}".into(),
                    "NEXTCLOUD_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["nextcloud_data:/var/www/html".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mariadb:11".into(),
                    ports: vec![],
                    env: vec![
                        "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                        "MYSQL_DATABASE=nextcloud".into(),
                        "MYSQL_USER=nextcloud".into(),
                        "MYSQL_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["nextcloud_db:/var/lib/mysql".into()],
                }],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Database password".into()), options: vec![] },
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "gitea".into(),
            name: "Gitea".into(),
            icon: "🍵".into(),
            category: "Dev Tools".into(),
            description: "Lightweight self-hosted Git service".into(),
            website: Some("https://gitea.io".into()),
            docker: Some(DockerTarget {
                image: "gitea/gitea:latest".into(),
                ports: vec!["3001:3000".into(), "2222:22".into()],
                env: vec![
                    "USER_UID=1000".into(),
                    "USER_GID=1000".into(),
                ],
                volumes: vec!["gitea_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── Monitoring ──
        AppManifest {
            id: "grafana".into(),
            name: "Grafana".into(),
            icon: "📊".into(),
            category: "Monitoring".into(),
            description: "Beautiful analytics and monitoring dashboards".into(),
            website: Some("https://grafana.com".into()),
            docker: Some(DockerTarget {
                image: "grafana/grafana:latest".into(),
                ports: vec!["3000:3000".into()],
                env: vec![
                    "GF_SECURITY_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["grafana_data:/var/lib/grafana".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "uptime-kuma".into(),
            name: "Uptime Kuma".into(),
            icon: "📈".into(),
            category: "Monitoring".into(),
            description: "Self-hosted monitoring tool like UptimeRobot".into(),
            website: Some("https://uptime.kuma.pet".into()),
            docker: Some(DockerTarget {
                image: "louislam/uptime-kuma:1".into(),
                ports: vec!["3002:3001".into()],
                env: vec![],
                volumes: vec!["uptime_kuma_data:/app/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "prometheus".into(),
            name: "Prometheus".into(),
            icon: "🔥".into(),
            category: "Monitoring".into(),
            description: "Systems and service monitoring with time-series database".into(),
            website: Some("https://prometheus.io".into()),
            docker: Some(DockerTarget {
                image: "prom/prometheus:latest".into(),
                ports: vec!["9090:9090".into()],
                env: vec![],
                volumes: vec!["prometheus_data:/prometheus".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── Database ──
        AppManifest {
            id: "postgres".into(),
            name: "PostgreSQL".into(),
            icon: "🐘".into(),
            category: "Database".into(),
            description: "Powerful, reliable, open-source relational database".into(),
            website: Some("https://www.postgresql.org".into()),
            docker: Some(DockerTarget {
                image: "postgres:16".into(),
                ports: vec!["5432:5432".into()],
                env: vec![
                    "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                    "POSTGRES_USER=${DB_USER}".into(),
                ],
                volumes: vec!["postgres_data:/var/lib/postgresql/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["postgresql".into()],
                packages_redhat: vec!["postgresql-server".into()],
                post_install: vec!["postgresql-setup --initdb || true".into()],
                service: Some("postgresql".into()),
            }),
            user_inputs: vec![
                UserInput { id: "DB_USER".into(), label: "Username".into(), input_type: "text".into(), default: Some("postgres".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Database password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "redis".into(),
            name: "Redis".into(),
            icon: "⚡".into(),
            category: "Database".into(),
            description: "In-memory data store used as cache, message broker, and database".into(),
            website: Some("https://redis.io".into()),
            docker: Some(DockerTarget {
                image: "redis:7-alpine".into(),
                ports: vec!["6379:6379".into()],
                env: vec![],
                volumes: vec!["redis_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["redis-server".into()],
                packages_redhat: vec!["redis".into()],
                post_install: vec![],
                service: Some("redis-server".into()),
            }),
            user_inputs: vec![],
        },

        AppManifest {
            id: "mariadb".into(),
            name: "MariaDB".into(),
            icon: "🐬".into(),
            category: "Database".into(),
            description: "Community-developed fork of MySQL — fast, stable, and open source".into(),
            website: Some("https://mariadb.org".into()),
            docker: Some(DockerTarget {
                image: "mariadb:11".into(),
                ports: vec!["3306:3306".into()],
                env: vec![
                    "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                    "MYSQL_DATABASE=${DB_NAME}".into(),
                ],
                volumes: vec!["mariadb_data:/var/lib/mysql".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y mariadb-server".into(),
                    "sed -i 's/bind-address.*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf".into(),
                    "systemctl enable mariadb".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["mariadb-server".into()],
                packages_redhat: vec!["mariadb-server".into()],
                post_install: vec!["systemctl enable mariadb".into()],
                service: Some("mariadb".into()),
            }),
            user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Root Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Root password".into()), options: vec![] },
                UserInput { id: "DB_NAME".into(), label: "Database Name".into(), input_type: "text".into(), default: Some("mydb".into()), required: false, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "mysql".into(),
            name: "MySQL".into(),
            icon: "🐬".into(),
            category: "Database".into(),
            description: "The world's most popular open-source relational database".into(),
            website: Some("https://www.mysql.com".into()),
            docker: Some(DockerTarget {
                image: "mysql:8.4".into(),
                ports: vec!["3307:3306".into()],
                env: vec![
                    "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                    "MYSQL_DATABASE=${DB_NAME}".into(),
                ],
                volumes: vec!["mysql_data:/var/lib/mysql".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y default-mysql-server".into(),
                    "sed -i 's/bind-address.*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf || true".into(),
                    "systemctl enable mysql".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["mysql-server".into()],
                packages_redhat: vec!["mysql-server".into()],
                post_install: vec!["systemctl enable mysqld".into()],
                service: Some("mysqld".into()),
            }),
            user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Root Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Root password".into()), options: vec![] },
                UserInput { id: "DB_NAME".into(), label: "Database Name".into(), input_type: "text".into(), default: Some("mydb".into()), required: false, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "galera-cluster".into(),
            name: "Galera Cluster".into(),
            icon: "🔄".into(),
            category: "Database".into(),
            description: "Synchronous multi-master replication for MariaDB — true high availability".into(),
            website: Some("https://galeracluster.com".into()),
            docker: Some(DockerTarget {
                image: "mariadb:11".into(),
                ports: vec!["3306:3306".into(), "4567:4567".into(), "4568:4568".into(), "4444:4444".into()],
                env: vec![
                    "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                    "MYSQL_INITDB_SKIP_TZINFO=1".into(),
                    "MARIADB_GALERA_CLUSTER_NAME=${CLUSTER_NAME}".into(),
                    "MARIADB_GALERA_CLUSTER_ADDRESS=gcomm://".into(),
                ],
                volumes: vec!["galera_data:/var/lib/mysql".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Root Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Root password".into()), options: vec![] },
                UserInput { id: "CLUSTER_NAME".into(), label: "Cluster Name".into(), input_type: "text".into(), default: Some("wolfstack_galera".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "mongodb".into(),
            name: "MongoDB".into(),
            icon: "🍃".into(),
            category: "Database".into(),
            description: "Document-oriented NoSQL database for modern applications".into(),
            website: Some("https://www.mongodb.com".into()),
            docker: Some(DockerTarget {
                image: "mongo:7".into(),
                ports: vec!["27017:27017".into()],
                env: vec![
                    "MONGO_INITDB_ROOT_USERNAME=${DB_USER}".into(),
                    "MONGO_INITDB_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                ],
                volumes: vec!["mongo_data:/data/db".into(), "mongo_config:/data/configdb".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "DB_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "sqlite-web".into(),
            name: "SQLite Web".into(),
            icon: "🪶".into(),
            category: "Database".into(),
            description: "Web-based SQLite database browser and manager in a container".into(),
            website: Some("https://github.com/nicois/sqlite-web".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/nicois/sqlite-web:latest".into(),
                ports: vec!["8085:8080".into()],
                env: vec![],
                volumes: vec!["sqlite_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── Networking ──
        AppManifest {
            id: "nginx".into(),
            name: "Nginx".into(),
            icon: "🔀".into(),
            category: "Networking".into(),
            description: "High-performance web server and reverse proxy".into(),
            website: Some("https://nginx.org".into()),
            docker: Some(DockerTarget {
                image: "nginx:alpine".into(),
                ports: vec!["8082:80".into(), "8443:443".into()],
                env: vec![],
                volumes: vec!["nginx_html:/usr/share/nginx/html".into(), "nginx_conf:/etc/nginx".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["nginx".into()],
                packages_redhat: vec!["nginx".into()],
                post_install: vec![],
                service: Some("nginx".into()),
            }),
            user_inputs: vec![],
        },

        AppManifest {
            id: "traefik".into(),
            name: "Traefik".into(),
            icon: "🚦".into(),
            category: "Networking".into(),
            description: "Modern reverse proxy and load balancer with auto SSL".into(),
            website: Some("https://traefik.io".into()),
            docker: Some(DockerTarget {
                image: "traefik:v3.0".into(),
                ports: vec!["80:80".into(), "443:443".into(), "8083:8080".into()],
                env: vec![],
                volumes: vec!["/var/run/docker.sock:/var/run/docker.sock:ro".into(), "traefik_data:/etc/traefik".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "pihole".into(),
            name: "Pi-hole".into(),
            icon: "🕳️".into(),
            category: "Networking".into(),
            description: "Network-wide ad blocker and DNS sinkhole".into(),
            website: Some("https://pi-hole.net".into()),
            docker: Some(DockerTarget {
                image: "pihole/pihole:latest".into(),
                ports: vec!["53:53/tcp".into(), "53:53/udp".into(), "8084:80".into()],
                env: vec![
                    "WEBPASSWORD=${ADMIN_PASSWORD}".into(),
                    "TZ=UTC".into(),
                ],
                volumes: vec!["pihole_config:/etc/pihole".into(), "pihole_dnsmasq:/etc/dnsmasq.d".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Web admin password".into()), options: vec![] },
            ],
        },

        // ── Media ──
        AppManifest {
            id: "jellyfin".into(),
            name: "Jellyfin".into(),
            icon: "🎬".into(),
            category: "Media".into(),
            description: "Free software media system for streaming movies and TV".into(),
            website: Some("https://jellyfin.org".into()),
            docker: Some(DockerTarget {
                image: "jellyfin/jellyfin:latest".into(),
                ports: vec!["8096:8096".into()],
                env: vec![],
                volumes: vec!["jellyfin_config:/config".into(), "jellyfin_cache:/cache".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── Other ──
        AppManifest {
            id: "portainer".into(),
            name: "Portainer".into(),
            icon: "🐳".into(),
            category: "Other".into(),
            description: "Docker management UI with container visualization".into(),
            website: Some("https://portainer.io".into()),
            docker: Some(DockerTarget {
                image: "portainer/portainer-ce:latest".into(),
                ports: vec!["9000:9000".into()],
                env: vec![],
                volumes: vec!["/var/run/docker.sock:/var/run/docker.sock".into(), "portainer_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "minio".into(),
            name: "MinIO".into(),
            icon: "📦".into(),
            category: "Other".into(),
            description: "High-performance S3-compatible object storage".into(),
            website: Some("https://min.io".into()),
            docker: Some(DockerTarget {
                image: "minio/minio:latest".into(),
                ports: vec!["9001:9001".into(), "9002:9000".into()],
                env: vec![
                    "MINIO_ROOT_USER=${ADMIN_USER}".into(),
                    "MINIO_ROOT_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["minio_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Root Username".into(), input_type: "text".into(), default: Some("minioadmin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Root Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Min 8 characters".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "code-server".into(),
            name: "Code Server".into(),
            icon: "💻".into(),
            category: "Dev Tools".into(),
            description: "VS Code in the browser — code from anywhere".into(),
            website: Some("https://coder.com".into()),
            docker: Some(DockerTarget {
                image: "lscr.io/linuxserver/code-server:latest".into(),
                ports: vec!["8443:8443".into()],
                env: vec![
                    "PASSWORD=${PASSWORD}".into(),
                    "PUID=1000".into(),
                    "PGID=1000".into(),
                    "TZ=UTC".into(),
                ],
                volumes: vec!["code_server_config:/config".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "PASSWORD".into(), label: "Access Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password to access the IDE".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "homeassistant".into(),
            name: "Home Assistant".into(),
            icon: "🏠".into(),
            category: "Other".into(),
            description: "Open-source home automation platform".into(),
            website: Some("https://www.home-assistant.io".into()),
            docker: Some(DockerTarget {
                image: "homeassistant/home-assistant:stable".into(),
                ports: vec!["8123:8123".into()],
                env: vec!["TZ=UTC".into()],
                volumes: vec!["homeassistant_config:/config".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },
    ]
}
