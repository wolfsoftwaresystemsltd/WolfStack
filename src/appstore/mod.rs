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


    Ok(result)
}

/// Uninstall an app by its install ID
pub fn uninstall_app(install_id: &str) -> Result<String, String> {
    let mut installed = load_installed();
    let idx = installed.iter().position(|a| a.install_id == install_id)
        .ok_or_else(|| format!("Install ID '{}' not found", install_id))?;

    let app = installed.remove(idx);


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


    // Install sidecars first (e.g. database)
    for sidecar in &docker.sidecars {
        let sidecar_name = format!("{}-{}", container_name, sidecar.name_suffix);
        let env = substitute_inputs(&sidecar.env, user_inputs);


        crate::containers::docker_pull(&sidecar.image)?;


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

    crate::containers::docker_pull(&docker.image)?;

    // Substitute user inputs into env vars
    let env = substitute_inputs(&docker.env, user_inputs);

    // Create the container (not started)

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


    // Create the container

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

    crate::containers::lxc_start(container_name)?;

    // Wait for the container to boot
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Run setup commands inside the container
    let commands = substitute_inputs(&lxc.setup_commands, user_inputs);
    for cmd in &commands {

        let output = std::process::Command::new("lxc-attach")
            .args(["-n", container_name, "--", "sh", "-c", cmd])
            .output()
            .map_err(|e| format!("Failed to run setup command: {}", e))?;

        if !output.status.success() {
            let _stderr = String::from_utf8_lossy(&output.stderr);

        }
    }

    // Stop the container — it's configured but not running

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

        let output = std::process::Command::new("sh")
            .args(["-c", cmd])
            .output()
            .map_err(|e| format!("Post-install command failed: {}", e))?;

        if !output.status.success() {
            let _stderr = String::from_utf8_lossy(&output.stderr);

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
        AppManifest {
            id: "superset".into(),
            name: "Apache Superset".into(),
            icon: "🔬".into(),
            category: "Analytics".into(),
            description: "Enterprise business intelligence and data exploration platform".into(),
            website: Some("https://superset.apache.org".into()),
            docker: Some(DockerTarget {
                image: "apache/superset:latest".into(),
                ports: vec!["8088:8088".into()],
                env: vec![
                    "SUPERSET_SECRET_KEY=${SECRET_KEY}".into(),
                ],
                volumes: vec!["superset_data:/app/superset_home".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Application secret key".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "appwrite".into(),
            name: "Appwrite".into(),
            icon: "🏗️".into(),
            category: "Dev Tools".into(),
            description: "Backend server for web, mobile, and Flutter developers".into(),
            website: Some("https://appwrite.io".into()),
            docker: Some(DockerTarget {
                image: "appwrite/appwrite:latest".into(),
                ports: vec!["8686:80".into()],
                env: vec![],
                volumes: vec!["appwrite_data:/storage".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },


        AppManifest {
            id: "authentik".into(),
            name: "Authentik".into(),
            icon: "🛡️".into(),
            category: "Security".into(),
            description: "Identity provider with SSO, MFA, and user management".into(),
            website: Some("https://goauthentik.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/goauthentik/server:latest".into(),
                ports: vec!["9003:9000".into(), "9444:9443".into()],
                env: vec![
                    "AUTHENTIK_SECRET_KEY=${SECRET_KEY}".into(),
                ],
                volumes: vec!["authentik_media:/media".into(), "authentik_templates:/templates".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Long random string".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "caprover".into(),
            name: "CapRover".into(),
            icon: "🚀".into(),
            category: "PaaS".into(),
            description: "Easy app/database deployment & server management — PaaS on your server".into(),
            website: Some("https://caprover.com".into()),
            docker: Some(DockerTarget {
                image: "caprover/caprover:latest".into(),
                ports: vec!["3000:3000".into(), "80:80".into(), "443:443".into()],
                env: vec![],
                volumes: vec!["/var/run/docker.sock:/var/run/docker.sock".into(), "/captain:/captain".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },


        AppManifest {
            id: "certbot".into(),
            name: "Certbot".into(),
            icon: "🔒".into(),
            category: "Wolf".into(),
            description: "Let's Encrypt certificate manager — free automatic HTTPS for your domains".into(),
            website: Some("https://certbot.eff.org".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y certbot".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["certbot".into()],
                packages_redhat: vec!["certbot".into()],
                post_install: vec![],
                service: None,
            }),
            user_inputs: vec![],
        },

        // ── Container Orchestration ──

        AppManifest {
            id: "cockroachdb".into(),
            name: "CockroachDB".into(),
            icon: "🪳".into(),
            category: "Database".into(),
            description: "Distributed SQL database for global, cloud-native applications".into(),
            website: Some("https://www.cockroachlabs.com".into()),
            docker: Some(DockerTarget {
                image: "cockroachdb/cockroach:latest".into(),
                ports: vec!["26257:26257".into(), "8888:8080".into()],
                env: vec![],
                volumes: vec!["cockroach_data:/cockroach/cockroach-data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
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
            id: "coolify".into(),
            name: "Coolify".into(),
            icon: "🧊".into(),
            category: "PaaS".into(),
            description: "Self-hosted Heroku/Netlify/Vercel alternative with Git push deploys".into(),
            website: Some("https://coolify.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/coollabsio/coolify:latest".into(),
                ports: vec!["8000:8000".into(), "6001:6001".into(), "6002:6002".into()],
                env: vec![],
                volumes: vec!["coolify_data:/data/coolify".into(), "/var/run/docker.sock:/var/run/docker.sock:ro".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },


        AppManifest {
            id: "crowdsec".into(),
            name: "CrowdSec".into(),
            icon: "🛡️".into(),
            category: "Security".into(),
            description: "Collaborative intrusion prevention — crowd-sourced threat intelligence".into(),
            website: Some("https://www.crowdsec.net".into()),
            docker: Some(DockerTarget {
                image: "crowdsecurity/crowdsec:latest".into(),
                ports: vec!["8585:8080".into(), "6060:6060".into()],
                env: vec![],
                volumes: vec!["crowdsec_data:/var/lib/crowdsec/data".into(), "crowdsec_config:/etc/crowdsec".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -s https://install.crowdsec.net | bash".into(),
                ],
                service: Some("crowdsec".into()),
            }),
            user_inputs: vec![],
        },

        // ── Communication ──

        AppManifest {
            id: "dify".into(),
            name: "Dify".into(),
            icon: "✨".into(),
            category: "AI / ML".into(),
            description: "LLM app development platform — build AI workflows visually".into(),
            website: Some("https://dify.ai".into()),
            docker: Some(DockerTarget {
                image: "langgenius/dify-api:latest".into(),
                ports: vec!["3006:5001".into()],
                env: vec![
                    "SECRET_KEY=${SECRET_KEY}".into(),
                ],
                volumes: vec!["dify_data:/app/api/storage".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Application secret key".into()), options: vec![] },
            ],
        },

        // ── Analytics ──

        AppManifest {
            id: "dokku".into(),
            name: "Dokku".into(),
            icon: "🐳".into(),
            category: "PaaS".into(),
            description: "Open-source PaaS — mini Heroku on your own server".into(),
            website: Some("https://dokku.com".into()),
            docker: None,
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -fsSL https://packagecloud.io/dokku/dokku/gpgkey | gpg --dearmor -o /usr/share/keyrings/dokku-archive-keyring.gpg".into(),
                    "echo 'deb [signed-by=/usr/share/keyrings/dokku-archive-keyring.gpg] https://packagecloud.io/dokku/dokku/ubuntu/ jammy main' | tee /etc/apt/sources.list.d/dokku.list".into(),
                    "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y dokku".into(),
                    "dokku plugin:install-dependencies --core".into(),
                ],
                service: None,
            }),
            user_inputs: vec![],
        },

        // ── CI/CD ──

        AppManifest {
            id: "drone".into(),
            name: "Drone CI".into(),
            icon: "🤖".into(),
            category: "CI/CD".into(),
            description: "Container-native continuous integration platform".into(),
            website: Some("https://www.drone.io".into()),
            docker: Some(DockerTarget {
                image: "drone/drone:latest".into(),
                ports: vec!["8180:80".into(), "8143:443".into()],
                env: vec![
                    "DRONE_SERVER_HOST=${DRONE_HOST}".into(),
                    "DRONE_SERVER_PROTO=https".into(),
                    "DRONE_RPC_SECRET=${RPC_SECRET}".into(),
                ],
                volumes: vec!["drone_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "DRONE_HOST".into(), label: "Server Hostname".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("e.g. drone.example.com".into()), options: vec![] },
                UserInput { id: "RPC_SECRET".into(), label: "RPC Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Shared secret between server and runners".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "elasticsearch".into(),
            name: "Elasticsearch".into(),
            icon: "🔎".into(),
            category: "Database".into(),
            description: "Distributed search and analytics engine for all types of data".into(),
            website: Some("https://www.elastic.co/elasticsearch".into()),
            docker: Some(DockerTarget {
                image: "docker.elastic.co/elasticsearch/elasticsearch:8.13.0".into(),
                ports: vec!["9200:9200".into(), "9300:9300".into()],
                env: vec![
                    "discovery.type=single-node".into(),
                    "ELASTIC_PASSWORD=${ELASTIC_PASSWORD}".into(),
                    "xpack.security.enabled=true".into(),
                ],
                volumes: vec!["es_data:/usr/share/elasticsearch/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ELASTIC_PASSWORD".into(), label: "Elastic Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password for elastic user".into()), options: vec![] },
            ],
        },

        // ── Monitoring (additions) ──

        AppManifest {
            id: "flowise".into(),
            name: "Flowise".into(),
            icon: "🌊".into(),
            category: "AI / ML".into(),
            description: "Drag-and-drop LLM flow builder for chatbots and AI agents".into(),
            website: Some("https://flowiseai.com".into()),
            docker: Some(DockerTarget {
                image: "flowiseai/flowise:latest".into(),
                ports: vec!["3005:3000".into()],
                env: vec![],
                volumes: vec!["flowise_data:/root/.flowise".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },


        AppManifest {
            id: "focalboard".into(),
            name: "Focalboard".into(),
            icon: "📋".into(),
            category: "Project Management".into(),
            description: "Open-source Trello/Notion/Asana alternative for project management".into(),
            website: Some("https://www.focalboard.com".into()),
            docker: Some(DockerTarget {
                image: "mattermost/focalboard:latest".into(),
                ports: vec!["8787:8000".into()],
                env: vec![],
                volumes: vec!["focalboard_data:/opt/focalboard/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── CMS & Publishing ──

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
            id: "ghost".into(),
            name: "Ghost".into(),
            icon: "👻".into(),
            category: "CMS".into(),
            description: "Professional publishing platform for blogs and newsletters".into(),
            website: Some("https://ghost.org".into()),
            docker: Some(DockerTarget {
                image: "ghost:5-alpine".into(),
                ports: vec!["2368:2368".into()],
                env: vec![
                    "url=${SITE_URL}".into(),
                ],
                volumes: vec!["ghost_data:/var/lib/ghost/content".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "SITE_URL".into(), label: "Site URL".into(), input_type: "text".into(), default: Some("http://localhost:2368".into()), required: true, placeholder: Some("e.g. https://blog.example.com".into()), options: vec![] },
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
            id: "gitlab-runner".into(),
            name: "GitLab Runner".into(),
            icon: "🦊".into(),
            category: "CI/CD".into(),
            description: "Run CI/CD jobs for GitLab pipelines".into(),
            website: Some("https://docs.gitlab.com/runner/".into()),
            docker: Some(DockerTarget {
                image: "gitlab/gitlab-runner:latest".into(),
                ports: vec![],
                env: vec![],
                volumes: vec!["gitlab_runner_config:/etc/gitlab-runner".into(), "/var/run/docker.sock:/var/run/docker.sock".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── Automation ──

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

        AppManifest {
            id: "wolfproxy".into(),
            name: "WolfProxy".into(),
            icon: "🐺".into(),
            category: "Wolf".into(),
            description: "Reverse proxy with built-in firewall and automatic SSL via Let's Encrypt".into(),
            website: Some("https://wolf.uk.com".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl".into(),
                    "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfProxy/main/setup.sh | bash".into(),
                    "systemctl enable wolfproxy".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfProxy/main/setup.sh | bash".into(),
                ],
                service: Some("wolfproxy".into()),
            }),
            user_inputs: vec![],
        },


        AppManifest {
            id: "hoppscotch".into(),
            name: "Hoppscotch".into(),
            icon: "🦗".into(),
            category: "Dev Tools".into(),
            description: "Open-source API development ecosystem — Postman alternative".into(),
            website: Some("https://hoppscotch.io".into()),
            docker: Some(DockerTarget {
                image: "hoppscotch/hoppscotch:latest".into(),
                ports: vec!["3012:3000".into()],
                env: vec![],
                volumes: vec!["hoppscotch_data:/app/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },


        AppManifest {
            id: "huginn".into(),
            name: "Huginn".into(),
            icon: "🤖".into(),
            category: "Automation".into(),
            description: "Build agents that perform automated tasks online — IFTTT on your server".into(),
            website: Some("https://github.com/huginn/huginn".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/huginn/huginn:latest".into(),
                ports: vec!["3003:3000".into()],
                env: vec![],
                volumes: vec!["huginn_data:/var/lib/mysql".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── AI / ML ──

        AppManifest {
            id: "immich".into(),
            name: "Immich".into(),
            icon: "📷".into(),
            category: "Media".into(),
            description: "Self-hosted Google Photos alternative — fast, beautiful photo management".into(),
            website: Some("https://immich.app".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/immich-app/immich-server:latest".into(),
                ports: vec!["2283:2283".into()],
                env: vec![
                    "DB_PASSWORD=${DB_PASSWORD}".into(),
                ],
                volumes: vec!["immich_upload:/usr/src/app/upload".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "tensorchord/pgvecto-rs:pg16-v0.2.1".into(),
                    ports: vec![],
                    env: vec![
                        "POSTGRES_DB=immich".into(),
                        "POSTGRES_USER=postgres".into(),
                        "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["immich_db:/var/lib/postgresql/data".into()],
                }],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },

        // ── File Sync ──

        AppManifest {
            id: "influxdb".into(),
            name: "InfluxDB".into(),
            icon: "📈".into(),
            category: "Database".into(),
            description: "Time-series database purpose-built for metrics, events, and IoT data".into(),
            website: Some("https://www.influxdata.com".into()),
            docker: Some(DockerTarget {
                image: "influxdb:2".into(),
                ports: vec!["8086:8086".into()],
                env: vec![
                    "DOCKER_INFLUXDB_INIT_MODE=setup".into(),
                    "DOCKER_INFLUXDB_INIT_USERNAME=${ADMIN_USER}".into(),
                    "DOCKER_INFLUXDB_INIT_PASSWORD=${ADMIN_PASSWORD}".into(),
                    "DOCKER_INFLUXDB_INIT_ORG=${ORG_NAME}".into(),
                    "DOCKER_INFLUXDB_INIT_BUCKET=${BUCKET_NAME}".into(),
                ],
                volumes: vec!["influxdb_data:/var/lib/influxdb2".into(), "influxdb_config:/etc/influxdb2".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Min 8 characters".into()), options: vec![] },
                UserInput { id: "ORG_NAME".into(), label: "Organisation".into(), input_type: "text".into(), default: Some("wolfstack".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "BUCKET_NAME".into(), label: "Default Bucket".into(), input_type: "text".into(), default: Some("default".into()), required: true, placeholder: None, options: vec![] },
            ],
        },


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
            id: "keycloak".into(),
            name: "Keycloak".into(),
            icon: "🔑".into(),
            category: "Security".into(),
            description: "Enterprise identity and access management — SSO for your apps".into(),
            website: Some("https://www.keycloak.org".into()),
            docker: Some(DockerTarget {
                image: "quay.io/keycloak/keycloak:latest".into(),
                ports: vec!["8484:8080".into()],
                env: vec![
                    "KEYCLOAK_ADMIN=${ADMIN_USER}".into(),
                    "KEYCLOAK_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                    "KC_HTTP_RELATIVE_PATH=/".into(),
                ],
                volumes: vec!["keycloak_data:/opt/keycloak/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Keycloak admin password".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "kubernetes".into(),
            name: "Kubernetes (K3s)".into(),
            icon: "☸️".into(),
            category: "Container Orchestration".into(),
            description: "Lightweight Kubernetes — production-ready K8s in a single binary".into(),
            website: Some("https://k3s.io".into()),
            docker: Some(DockerTarget {
                image: "rancher/k3s:latest".into(),
                ports: vec!["6443:6443".into(), "80:80".into(), "443:443".into()],
                env: vec![
                    "K3S_TOKEN=${K3S_TOKEN}".into(),
                ],
                volumes: vec!["k3s_data:/var/lib/rancher/k3s".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sfL https://get.k3s.io | sh -".into(),
                ],
                service: Some("k3s".into()),
            }),
            user_inputs: vec![
                UserInput { id: "K3S_TOKEN".into(), label: "Cluster Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Shared secret for joining nodes".into()), options: vec![] },
            ],
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
            id: "matrix-synapse".into(),
            name: "Matrix (Synapse)".into(),
            icon: "🔗".into(),
            category: "Communication".into(),
            description: "Decentralized, end-to-end encrypted messaging and collaboration".into(),
            website: Some("https://matrix.org".into()),
            docker: Some(DockerTarget {
                image: "matrixdotorg/synapse:latest".into(),
                ports: vec!["8008:8008".into(), "8448:8448".into()],
                env: vec![
                    "SYNAPSE_SERVER_NAME=${SERVER_NAME}".into(),
                    "SYNAPSE_REPORT_STATS=no".into(),
                ],
                volumes: vec!["synapse_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("e.g. matrix.example.com".into()), options: vec![] },
            ],
        },

        // ── Project Management ──

        AppManifest {
            id: "mattermost".into(),
            name: "Mattermost".into(),
            icon: "💬".into(),
            category: "Communication".into(),
            description: "Secure messaging for teams — open-source and self-hosted".into(),
            website: Some("https://mattermost.com".into()),
            docker: Some(DockerTarget {
                image: "mattermost/mattermost-team-edition:latest".into(),
                ports: vec!["8065:8065".into()],
                env: vec![
                    "MM_SQLSETTINGS_DRIVERNAME=postgres".into(),
                    "MM_SQLSETTINGS_DATASOURCE=postgres://mattermost:${DB_PASSWORD}@${CONTAINER_NAME}-db:5432/mattermost?sslmode=disable".into(),
                ],
                volumes: vec!["mattermost_data:/mattermost/data".into(), "mattermost_config:/mattermost/config".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "postgres:16-alpine".into(),
                    ports: vec![],
                    env: vec![
                        "POSTGRES_DB=mattermost".into(),
                        "POSTGRES_USER=mattermost".into(),
                        "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["mattermost_db:/var/lib/postgresql/data".into()],
                }],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "meilisearch".into(),
            name: "Meilisearch".into(),
            icon: "🔍".into(),
            category: "Database".into(),
            description: "Lightning fast, typo-tolerant search engine".into(),
            website: Some("https://www.meilisearch.com".into()),
            docker: Some(DockerTarget {
                image: "getmeili/meilisearch:latest".into(),
                ports: vec!["7700:7700".into()],
                env: vec![
                    "MEILI_MASTER_KEY=${MASTER_KEY}".into(),
                ],
                volumes: vec!["meilisearch_data:/meili_data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "MASTER_KEY".into(), label: "Master Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("API master key (min 16 chars)".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "metabase".into(),
            name: "Metabase".into(),
            icon: "📉".into(),
            category: "Analytics".into(),
            description: "Business intelligence dashboards and data exploration for everyone".into(),
            website: Some("https://www.metabase.com".into()),
            docker: Some(DockerTarget {
                image: "metabase/metabase:latest".into(),
                ports: vec!["3008:3000".into()],
                env: vec![],
                volumes: vec!["metabase_data:/metabase-data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── Security ──

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
            id: "n8n".into(),
            name: "n8n".into(),
            icon: "⚡".into(),
            category: "Automation".into(),
            description: "Workflow automation platform — open-source Zapier alternative".into(),
            website: Some("https://n8n.io".into()),
            docker: Some(DockerTarget {
                image: "n8nio/n8n:latest".into(),
                ports: vec!["5678:5678".into()],
                env: vec![
                    "N8N_BASIC_AUTH_ACTIVE=true".into(),
                    "N8N_BASIC_AUTH_USER=${ADMIN_USER}".into(),
                    "N8N_BASIC_AUTH_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["n8n_data:/home/node/.n8n".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password for n8n UI".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "netdata".into(),
            name: "Netdata".into(),
            icon: "📡".into(),
            category: "Monitoring".into(),
            description: "Real-time performance and health monitoring for systems and apps".into(),
            website: Some("https://www.netdata.cloud".into()),
            docker: Some(DockerTarget {
                image: "netdata/netdata:latest".into(),
                ports: vec!["19999:19999".into()],
                env: vec![],
                volumes: vec!["netdata_config:/etc/netdata".into(), "netdata_lib:/var/lib/netdata".into(), "netdata_cache:/var/cache/netdata".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -fsSL https://get.netdata.cloud/kickstart.sh | bash".into(),
                ],
                service: Some("netdata".into()),
            }),
            user_inputs: vec![],
        },

        // ── Dev Tools (additions) ──

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
            id: "nocodb".into(),
            name: "NocoDB".into(),
            icon: "📊".into(),
            category: "Dev Tools".into(),
            description: "Open-source Airtable alternative — turn any database into a spreadsheet".into(),
            website: Some("https://nocodb.com".into()),
            docker: Some(DockerTarget {
                image: "nocodb/nocodb:latest".into(),
                ports: vec!["8686:8080".into()],
                env: vec![],
                volumes: vec!["nocodb_data:/usr/app/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── Networking (additions) ──

        AppManifest {
            id: "nomad".into(),
            name: "Nomad".into(),
            icon: "📦".into(),
            category: "Container Orchestration".into(),
            description: "HashiCorp workload orchestrator for containers and non-containerized apps".into(),
            website: Some("https://www.nomadproject.io".into()),
            docker: Some(DockerTarget {
                image: "hashicorp/nomad:latest".into(),
                ports: vec!["4646:4646".into(), "4647:4647".into(), "4648:4648".into()],
                env: vec![],
                volumes: vec!["nomad_data:/nomad/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── PaaS & Deployment ──

        AppManifest {
            id: "ollama".into(),
            name: "Ollama".into(),
            icon: "🦙".into(),
            category: "AI / ML".into(),
            description: "Run large language models locally — Llama, Mistral, Gemma and more".into(),
            website: Some("https://ollama.com".into()),
            docker: Some(DockerTarget {
                image: "ollama/ollama:latest".into(),
                ports: vec!["11434:11434".into()],
                env: vec![],
                volumes: vec!["ollama_data:/root/.ollama".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -fsSL https://ollama.com/install.sh | sh".into(),
                ],
                service: Some("ollama".into()),
            }),
            user_inputs: vec![],
        },


        AppManifest {
            id: "open-webui".into(),
            name: "Open WebUI".into(),
            icon: "🧠".into(),
            category: "AI / ML".into(),
            description: "ChatGPT-style interface for local LLMs — works with Ollama".into(),
            website: Some("https://openwebui.com".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/open-webui/open-webui:main".into(),
                ports: vec!["3004:8080".into()],
                env: vec![],
                volumes: vec!["open_webui_data:/app/backend/data".into()],
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
            id: "plane".into(),
            name: "Plane".into(),
            icon: "✈️".into(),
            category: "Project Management".into(),
            description: "Open-source Jira/Linear alternative — issue tracking and project planning".into(),
            website: Some("https://plane.so".into()),
            docker: Some(DockerTarget {
                image: "makeplane/plane-frontend:latest".into(),
                ports: vec!["3010:3000".into()],
                env: vec![],
                volumes: vec!["plane_data:/app/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },


        AppManifest {
            id: "plausible".into(),
            name: "Plausible Analytics".into(),
            icon: "📊".into(),
            category: "Analytics".into(),
            description: "Privacy-friendly Google Analytics alternative — no cookies".into(),
            website: Some("https://plausible.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/plausible/community-edition:latest".into(),
                ports: vec!["8282:8000".into()],
                env: vec![
                    "BASE_URL=${BASE_URL}".into(),
                    "SECRET_KEY_BASE=${SECRET_KEY}".into(),
                ],
                volumes: vec!["plausible_data:/var/lib/plausible".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "BASE_URL".into(), label: "Base URL".into(), input_type: "text".into(), default: Some("http://localhost:8282".into()), required: true, placeholder: Some("e.g. https://analytics.example.com".into()), options: vec![] },
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("64-character secret".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "pocketbase".into(),
            name: "PocketBase".into(),
            icon: "📱".into(),
            category: "Dev Tools".into(),
            description: "Open-source backend in a single file — SQLite + Auth + Realtime".into(),
            website: Some("https://pocketbase.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/muchobien/pocketbase:latest".into(),
                ports: vec!["8090:8090".into()],
                env: vec![],
                volumes: vec!["pocketbase_data:/pb_data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── Search ──

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
            id: "rocketchat".into(),
            name: "Rocket.Chat".into(),
            icon: "💬".into(),
            category: "Communication".into(),
            description: "Team communication platform — open-source Slack alternative".into(),
            website: Some("https://rocket.chat".into()),
            docker: Some(DockerTarget {
                image: "rocketchat/rocket.chat:latest".into(),
                ports: vec!["3009:3000".into()],
                env: vec![
                    "MONGO_URL=mongodb://${CONTAINER_NAME}-db:27017/rocketchat".into(),
                    "ROOT_URL=${ROOT_URL}".into(),
                ],
                volumes: vec!["rocketchat_uploads:/app/uploads".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mongo:6".into(),
                    ports: vec![],
                    env: vec![],
                    volumes: vec!["rocketchat_db:/data/db".into()],
                }],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ROOT_URL".into(), label: "Root URL".into(), input_type: "text".into(), default: Some("http://localhost:3009".into()), required: true, placeholder: Some("e.g. https://chat.example.com".into()), options: vec![] },
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
            id: "strapi".into(),
            name: "Strapi".into(),
            icon: "🚀".into(),
            category: "CMS".into(),
            description: "Leading open-source headless CMS — 100% JavaScript/TypeScript".into(),
            website: Some("https://strapi.io".into()),
            docker: Some(DockerTarget {
                image: "strapi/strapi:latest".into(),
                ports: vec!["1337:1337".into()],
                env: vec![],
                volumes: vec!["strapi_data:/srv/app".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },

        // ── Photo & Media ──

        AppManifest {
            id: "supabase".into(),
            name: "Supabase".into(),
            icon: "⚡".into(),
            category: "Dev Tools".into(),
            description: "Firebase alternative — Postgres + Auth + Storage + Realtime APIs".into(),
            website: Some("https://supabase.com".into()),
            docker: Some(DockerTarget {
                image: "supabase/studio:latest".into(),
                ports: vec!["3011:3000".into()],
                env: vec![],
                volumes: vec!["supabase_data:/var/lib/supabase".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![],
        },


        AppManifest {
            id: "syncthing".into(),
            name: "Syncthing".into(),
            icon: "🔄".into(),
            category: "Other".into(),
            description: "Continuous peer-to-peer file synchronization between devices".into(),
            website: Some("https://syncthing.net".into()),
            docker: Some(DockerTarget {
                image: "syncthing/syncthing:latest".into(),
                ports: vec!["8384:8384".into(), "22000:22000/tcp".into(), "22000:22000/udp".into(), "21027:21027/udp".into()],
                env: vec![],
                volumes: vec!["syncthing_data:/var/syncthing".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["syncthing".into()],
                packages_redhat: vec!["syncthing".into()],
                post_install: vec![],
                service: Some("syncthing@root".into()),
            }),
            user_inputs: vec![],
        },

        // ── Backend / BaaS ──

        AppManifest {
            id: "taiga".into(),
            name: "Taiga".into(),
            icon: "🌲".into(),
            category: "Project Management".into(),
            description: "Agile project management for cross-functional teams".into(),
            website: Some("https://taiga.io".into()),
            docker: Some(DockerTarget {
                image: "taigaio/taiga-back:latest".into(),
                ports: vec!["8686:8000".into()],
                env: vec![],
                volumes: vec!["taiga_data:/taiga-back/media".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
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
            id: "umami".into(),
            name: "Umami".into(),
            icon: "📈".into(),
            category: "Analytics".into(),
            description: "Simple, fast, privacy-focused website analytics".into(),
            website: Some("https://umami.is".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/umami-software/umami:postgresql-latest".into(),
                ports: vec!["3007:3000".into()],
                env: vec![
                    "DATABASE_URL=postgresql://umami:${DB_PASSWORD}@${CONTAINER_NAME}-db:5432/umami".into(),
                ],
                volumes: vec![],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "postgres:16-alpine".into(),
                    ports: vec![],
                    env: vec![
                        "POSTGRES_DB=umami".into(),
                        "POSTGRES_USER=umami".into(),
                        "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["umami_db:/var/lib/postgresql/data".into()],
                }],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
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
            id: "vaultwarden".into(),
            name: "Vaultwarden".into(),
            icon: "🔐".into(),
            category: "Security".into(),
            description: "Bitwarden-compatible password manager — lightweight and self-hosted".into(),
            website: Some("https://github.com/dani-garcia/vaultwarden".into()),
            docker: Some(DockerTarget {
                image: "vaultwarden/server:latest".into(),
                ports: vec!["8383:80".into()],
                env: vec![
                    "ADMIN_TOKEN=${ADMIN_TOKEN}".into(),
                ],
                volumes: vec!["vaultwarden_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_TOKEN".into(), label: "Admin Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Token for admin panel access".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "wireguard".into(),
            name: "WireGuard".into(),
            icon: "🔒".into(),
            category: "Networking".into(),
            description: "Fast, modern VPN using state-of-the-art cryptography".into(),
            website: Some("https://www.wireguard.com".into()),
            docker: None,
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["wireguard".into(), "wireguard-tools".into()],
                packages_redhat: vec!["wireguard-tools".into()],
                post_install: vec![
                    "wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey".into(),
                    "chmod 600 /etc/wireguard/privatekey".into(),
                ],
                service: Some("wg-quick@wg0".into()),
            }),
            user_inputs: vec![],
        },

        // ── Database (additions) ──

        AppManifest {
            id: "wolfdisk".into(),
            name: "WolfDisk".into(),
            icon: "🐺".into(),
            category: "Wolf".into(),
            description: "Distributed filesystem for seamless storage across your cluster".into(),
            website: Some("https://wolf.uk.com".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl".into(),
                    "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/setup.sh | bash -s -- --component wolfdisk".into(),
                    "systemctl enable wolfdisk".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/setup.sh | bash -s -- --component wolfdisk".into(),
                ],
                service: Some("wolfdisk".into()),
            }),
            user_inputs: vec![],
        },


        AppManifest {
            id: "wolfscale".into(),
            name: "WolfScale".into(),
            icon: "🐺".into(),
            category: "Wolf".into(),
            description: "MariaDB-compatible distributed database with automatic replication".into(),
            website: Some("https://wolf.uk.com".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl".into(),
                    "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/setup.sh | bash -s -- --component wolfscale".into(),
                    "systemctl enable wolfscale".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfScale/main/setup.sh | bash -s -- --component wolfscale".into(),
                ],
                service: Some("wolfscale".into()),
            }),
            user_inputs: vec![],
        },


        AppManifest {
            id: "wolfserve".into(),
            name: "WolfServe".into(),
            icon: "🐺".into(),
            category: "Wolf".into(),
            description: "High-performance web server for static sites and applications".into(),
            website: Some("https://wolf.uk.com".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl".into(),
                    "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfServe/main/setup.sh | bash".into(),
                    "systemctl enable wolfserve".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfServe/main/setup.sh | bash".into(),
                ],
                service: Some("wolfserve".into()),
            }),
            user_inputs: vec![],
        },


        AppManifest {
            id: "woodpecker".into(),
            name: "Woodpecker CI".into(),
            icon: "🪶".into(),
            category: "CI/CD".into(),
            description: "Lightweight CI/CD engine with great extensibility".into(),
            website: Some("https://woodpecker-ci.org".into()),
            docker: Some(DockerTarget {
                image: "woodpeckerci/woodpecker-server:latest".into(),
                ports: vec!["8200:8000".into()],
                env: vec![
                    "WOODPECKER_OPEN=true".into(),
                    "WOODPECKER_ADMIN=${ADMIN_USER}".into(),
                ],
                volumes: vec!["woodpecker_data:/var/lib/woodpecker".into()],
                sidecars: vec![],
            }),
            lxc: None,
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
            ],
        },


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

        // ── New: Trending & Self-Hosted Favourites ──

        AppManifest {
            id: "uptime-kuma".into(),
            name: "Uptime Kuma".into(),
            icon: "📈".into(),
            category: "Monitoring".into(),
            description: "Self-hosted uptime monitoring tool with beautiful status pages".into(),
            website: Some("https://github.com/louislam/uptime-kuma".into()),
            docker: Some(DockerTarget {
                image: "louislam/uptime-kuma:latest".into(),
                ports: vec!["3001:3001".into()],
                env: vec![],
                volumes: vec!["uptime_kuma_data:/app/data".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs".into(),
                    "git clone https://github.com/louislam/uptime-kuma.git /opt/uptime-kuma".into(),
                    "cd /opt/uptime-kuma && npm run setup".into(),
                    "cat > /etc/systemd/system/uptime-kuma.service << 'EOF'\n[Unit]\nDescription=Uptime Kuma\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/uptime-kuma\nExecStart=/usr/bin/node server/server.js\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable uptime-kuma".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "vaultwarden".into(),
            name: "Vaultwarden".into(),
            icon: "🔐".into(),
            category: "Security".into(),
            description: "Lightweight Bitwarden-compatible password manager server".into(),
            website: Some("https://github.com/dani-garcia/vaultwarden".into()),
            docker: Some(DockerTarget {
                image: "vaultwarden/server:latest".into(),
                ports: vec!["8780:80".into()],
                env: vec![
                    "ADMIN_TOKEN=${ADMIN_TOKEN}".into(),
                ],
                volumes: vec!["vaultwarden_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl wget libssl3 ca-certificates".into(),
                    "mkdir -p /opt/vaultwarden /var/lib/vaultwarden".into(),
                    "wget -O /tmp/vw.tar.gz https://github.com/dani-garcia/vaultwarden/releases/latest/download/vaultwarden-linux-x86_64.tar.gz || echo 'Download may require manual setup'".into(),
                    "cat > /etc/systemd/system/vaultwarden.service << 'EOF'\n[Unit]\nDescription=Vaultwarden\nAfter=network.target\n[Service]\nEnvironment=DATA_FOLDER=/var/lib/vaultwarden\nEnvironment=ADMIN_TOKEN=${ADMIN_TOKEN}\nExecStart=/opt/vaultwarden/vaultwarden\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable vaultwarden".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_TOKEN".into(), label: "Admin Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Secret token for admin panel access".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "paperless-ngx".into(),
            name: "Paperless-ngx".into(),
            icon: "📄".into(),
            category: "Productivity".into(),
            description: "Document management system that transforms physical documents into a searchable archive".into(),
            website: Some("https://docs.paperless-ngx.com".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/paperless-ngx/paperless-ngx:latest".into(),
                ports: vec!["8777:8000".into()],
                env: vec![
                    "PAPERLESS_SECRET_KEY=${SECRET_KEY}".into(),
                    "PAPERLESS_ADMIN_USER=admin".into(),
                    "PAPERLESS_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["paperless_data:/usr/src/paperless/data".into(), "paperless_media:/usr/src/paperless/media".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y python3 python3-pip python3-venv redis-server imagemagick gnupg2 curl".into(),
                    "pip3 install paperless-ngx || echo 'Install via Docker recommended for production'".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Application secret key".into()), options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password for admin user".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "opencti".into(),
            name: "OpenCTI".into(),
            icon: "🔍".into(),
            category: "Security".into(),
            description: "Open Cyber Threat Intelligence Platform — knowledge management for threat analysis".into(),
            website: Some("https://github.com/OpenCTI-Platform/opencti".into()),
            docker: Some(DockerTarget {
                image: "opencti/platform:latest".into(),
                ports: vec!["8787:8080".into()],
                env: vec![
                    "OPENCTI_ADMIN_EMAIL=${ADMIN_EMAIL}".into(),
                    "OPENCTI_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                    "OPENCTI_ADMIN_TOKEN=${ADMIN_TOKEN}".into(),
                ],
                volumes: vec!["opencti_data:/opt/opencti/data".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git nodejs npm python3 python3-pip".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs".into(),
                    "git clone https://github.com/OpenCTI-Platform/opencti.git /opt/opencti".into(),
                    "cd /opt/opencti && npm install".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_EMAIL".into(), label: "Admin Email".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("admin@example.com".into()), options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Strong admin password".into()), options: vec![] },
                UserInput { id: "ADMIN_TOKEN".into(), label: "Admin API Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("UUID for API access".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "outline".into(),
            name: "Outline".into(),
            icon: "📝".into(),
            category: "Productivity".into(),
            description: "Beautiful wiki and knowledge base for growing teams — Notion alternative".into(),
            website: Some("https://getoutline.com".into()),
            docker: Some(DockerTarget {
                image: "outlinewiki/outline:latest".into(),
                ports: vec!["3003:3000".into()],
                env: vec![
                    "SECRET_KEY=${SECRET_KEY}".into(),
                    "UTILS_SECRET=${UTILS_SECRET}".into(),
                    "DATABASE_URL=postgres://outline:${DB_PASSWORD}@${CONTAINER_NAME}-db:5432/outline".into(),
                    "REDIS_URL=redis://${CONTAINER_NAME}-redis:6379".into(),
                    "URL=http://localhost:3003".into(),
                ],
                volumes: vec!["outline_data:/var/lib/outline/data".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs postgresql redis-server".into(),
                    "systemctl enable postgresql redis-server".into(),
                    "systemctl start postgresql redis-server".into(),
                    "su - postgres -c \"createuser outline && createdb -O outline outline\"".into(),
                    "git clone https://github.com/outline/outline.git /opt/outline".into(),
                    "cd /opt/outline && npm install && npm run build".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Long random hex string".into()), options: vec![] },
                UserInput { id: "UTILS_SECRET".into(), label: "Utils Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Another random hex string".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "supabase".into(),
            name: "Supabase".into(),
            icon: "⚡".into(),
            category: "Dev Tools".into(),
            description: "Open-source Firebase alternative with Postgres, Auth, Storage, and Realtime".into(),
            website: Some("https://supabase.com".into()),
            docker: Some(DockerTarget {
                image: "supabase/studio:latest".into(),
                ports: vec!["3004:3000".into()],
                env: vec![
                    "SUPABASE_URL=http://localhost:8000".into(),
                    "SUPABASE_ANON_KEY=${ANON_KEY}".into(),
                ],
                volumes: vec!["supabase_data:/var/lib/supabase".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git docker.io docker-compose".into(),
                    "git clone --depth 1 https://github.com/supabase/supabase.git /opt/supabase".into(),
                    "cd /opt/supabase/docker && cp .env.example .env".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ANON_KEY".into(), label: "Anonymous Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Supabase anonymous API key".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "stirling-pdf".into(),
            name: "Stirling PDF".into(),
            icon: "📑".into(),
            category: "Productivity".into(),
            description: "Self-hosted PDF manipulation tool — merge, split, convert, compress and more".into(),
            website: Some("https://github.com/Stirling-Tools/Stirling-PDF".into()),
            docker: Some(DockerTarget {
                image: "frooodle/s-pdf:latest".into(),
                ports: vec!["8484:8080".into()],
                env: vec![],
                volumes: vec!["stirling_data:/usr/share/tesseract-ocr".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git openjdk-17-jre-headless libreoffice-core".into(),
                    "git clone https://github.com/Stirling-Tools/Stirling-PDF.git /opt/stirling-pdf".into(),
                    "cd /opt/stirling-pdf && ./gradlew build -x test || echo 'Build may require additional setup'".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "flagsmith".into(),
            name: "Flagsmith".into(),
            icon: "🚩".into(),
            category: "Dev Tools".into(),
            description: "Open-source feature flag and remote configuration service".into(),
            website: Some("https://flagsmith.com".into()),
            docker: Some(DockerTarget {
                image: "flagsmith/flagsmith:latest".into(),
                ports: vec!["8600:8000".into()],
                env: vec![],
                volumes: vec!["flagsmith_data:/var/lib/flagsmith".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git python3 python3-pip python3-venv postgresql".into(),
                    "systemctl enable --now postgresql".into(),
                    "su - postgres -c \"createuser flagsmith && createdb -O flagsmith flagsmith\"".into(),
                    "git clone https://github.com/Flagsmith/flagsmith.git /opt/flagsmith".into(),
                    "cd /opt/flagsmith/api && python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "infisical".into(),
            name: "Infisical".into(),
            icon: "🔑".into(),
            category: "Security".into(),
            description: "Open-source secret management platform — sync secrets across your team and infrastructure".into(),
            website: Some("https://infisical.com".into()),
            docker: Some(DockerTarget {
                image: "infisical/infisical:latest".into(),
                ports: vec!["8585:8080".into()],
                env: vec![
                    "ENCRYPTION_KEY=${ENCRYPTION_KEY}".into(),
                ],
                volumes: vec!["infisical_data:/var/lib/infisical".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs mongodb-org || apt-get install -y nodejs".into(),
                    "git clone https://github.com/Infisical/infisical.git /opt/infisical".into(),
                    "cd /opt/infisical && npm install".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ENCRYPTION_KEY".into(), label: "Encryption Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("128-bit hex encryption key".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "it-tools".into(),
            name: "IT Tools".into(),
            icon: "🧰".into(),
            category: "Dev Tools".into(),
            description: "Collection of handy online tools for developers — converters, generators, formatters".into(),
            website: Some("https://github.com/CorentinTh/it-tools".into()),
            docker: Some(DockerTarget {
                image: "corentinth/it-tools:latest".into(),
                ports: vec!["8383:80".into()],
                env: vec![],
                volumes: vec![],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs".into(),
                    "git clone https://github.com/CorentinTh/it-tools.git /opt/it-tools".into(),
                    "cd /opt/it-tools && npm install && npm run build".into(),
                    "apt-get install -y nginx".into(),
                    "cp -r /opt/it-tools/dist/* /var/www/html/".into(),
                    "systemctl enable nginx".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "searxng".into(),
            name: "SearXNG".into(),
            icon: "🌍".into(),
            category: "Privacy".into(),
            description: "Privacy-respecting, hackable metasearch engine aggregating results from 70+ search services".into(),
            website: Some("https://searxng.org".into()),
            docker: Some(DockerTarget {
                image: "searxng/searxng:latest".into(),
                ports: vec!["8282:8080".into()],
                env: vec![],
                volumes: vec!["searxng_data:/etc/searxng".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y python3 python3-pip python3-venv git".into(),
                    "git clone https://github.com/searxng/searxng.git /opt/searxng".into(),
                    "cd /opt/searxng && python3 -m venv venv && . venv/bin/activate && pip install -e .".into(),
                    "cat > /etc/systemd/system/searxng.service << 'EOF'\n[Unit]\nDescription=SearXNG\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/searxng\nExecStart=/opt/searxng/venv/bin/python -m searx.webapp\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable searxng".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "excalidraw".into(),
            name: "Excalidraw".into(),
            icon: "🎨".into(),
            category: "Productivity".into(),
            description: "Virtual whiteboard for sketching hand-drawn like diagrams — collaborative".into(),
            website: Some("https://excalidraw.com".into()),
            docker: Some(DockerTarget {
                image: "excalidraw/excalidraw:latest".into(),
                ports: vec!["8686:80".into()],
                env: vec![],
                volumes: vec![],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs".into(),
                    "git clone https://github.com/excalidraw/excalidraw.git /opt/excalidraw".into(),
                    "cd /opt/excalidraw && npm install && npm run build:app".into(),
                    "apt-get install -y nginx".into(),
                    "cp -r /opt/excalidraw/build/* /var/www/html/".into(),
                    "systemctl enable nginx".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "rallly".into(),
            name: "Rallly".into(),
            icon: "📅".into(),
            category: "Productivity".into(),
            description: "Self-hosted Doodle alternative — schedule group meetings without the back and forth".into(),
            website: Some("https://rallly.co".into()),
            docker: Some(DockerTarget {
                image: "lukevella/rallly:latest".into(),
                ports: vec!["3007:3000".into()],
                env: vec![
                    "SECRET_PASSWORD=${SECRET_KEY}".into(),
                    "DATABASE_URL=postgres://rallly:${DB_PASSWORD}@${CONTAINER_NAME}-db:5432/rallly".into(),
                ],
                volumes: vec![],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git postgresql".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs".into(),
                    "systemctl enable --now postgresql".into(),
                    "su - postgres -c \"createuser rallly && createdb -O rallly rallly\"".into(),
                    "git clone https://github.com/lukevella/rallly.git /opt/rallly".into(),
                    "cd /opt/rallly && npm install && npm run build".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "zitadel".into(),
            name: "Zitadel".into(),
            icon: "🛂".into(),
            category: "Security".into(),
            description: "Cloud-native identity management — SSO, MFA, and user management in one platform".into(),
            website: Some("https://zitadel.com".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/zitadel/zitadel:latest".into(),
                ports: vec!["8282:8080".into()],
                env: vec![
                    "ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME=admin".into(),
                    "ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["zitadel_data:/data".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl wget".into(),
                    "wget -O /tmp/zitadel.tar.gz https://github.com/zitadel/zitadel/releases/latest/download/zitadel-linux-amd64.tar.gz".into(),
                    "mkdir -p /opt/zitadel && tar xzf /tmp/zitadel.tar.gz -C /opt/zitadel".into(),
                    "cat > /etc/systemd/system/zitadel.service << 'EOF'\n[Unit]\nDescription=Zitadel Identity Platform\nAfter=network.target\n[Service]\nExecStart=/opt/zitadel/zitadel start-from-init --masterkey \"MasterkeyNeedsToHave32Chars!!\" --tlsMode disabled\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable zitadel".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Initial admin password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "changedetection".into(),
            name: "Changedetection.io".into(),
            icon: "👁️".into(),
            category: "Monitoring".into(),
            description: "Website change detection and monitoring — get notified when web pages change".into(),
            website: Some("https://changedetection.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/dgtlmoon/changedetection.io:latest".into(),
                ports: vec!["5000:5000".into()],
                env: vec![],
                volumes: vec!["changedetection_data:/datastore".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y python3 python3-pip python3-venv git".into(),
                    "git clone https://github.com/dgtlmoon/changedetection.io.git /opt/changedetection".into(),
                    "cd /opt/changedetection && python3 -m venv venv && . venv/bin/activate && pip install -e .".into(),
                    "cat > /etc/systemd/system/changedetection.service << 'EOF'\n[Unit]\nDescription=Changedetection.io\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/changedetection\nExecStart=/opt/changedetection/venv/bin/changedetection.io -d /var/lib/changedetection -p 5000\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "mkdir -p /var/lib/changedetection".into(),
                    "systemctl enable changedetection".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![],
        },

        AppManifest {
            id: "picoclaw".into(),
            name: "PicoClaw".into(),
            icon: "🦞".into(),
            category: "AI / ML".into(),
            description: "Ultra-efficient AI assistant in Go — tiny footprint, deploys anywhere, 10MB RAM, 1s boot".into(),
            website: Some("https://github.com/sipeed/picoclaw".into()),
            docker: Some(DockerTarget {
                image: "sipeed/picoclaw:latest".into(),
                ports: vec!["8686:8686".into()],
                env: vec![],
                volumes: vec!["picoclaw_config:/app/config".into()],
                sidecars: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git make gcc".into(),
                    "curl -fsSL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xzf -".into(),
                    "export PATH=$PATH:/usr/local/go/bin && git clone https://github.com/sipeed/picoclaw.git /opt/picoclaw".into(),
                    "cd /opt/picoclaw && export PATH=$PATH:/usr/local/go/bin && make deps && make build".into(),
                    "cp /opt/picoclaw/config/config.example.json /opt/picoclaw/config/config.json".into(),
                    "cat > /etc/systemd/system/picoclaw.service << 'EOF'\n[Unit]\nDescription=PicoClaw AI Assistant\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/picoclaw\nExecStart=/opt/picoclaw/picoclaw\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable picoclaw".into(),
                ],
            }),
            bare_metal: None,
            user_inputs: vec![],
        },

    ]
}
