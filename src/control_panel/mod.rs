// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Control Panel — a single cluster-wide view for every VM, LXC and
//! Docker container across every node, with user-configurable grouping
//! (by Node, Type, Status, Cluster or user-defined Custom groups) and
//! drag-and-drop membership management for the Custom axis.
//!
//! This module owns the persistent custom-group config and the
//! cluster-wide inventory aggregator. The group-by axes other than
//! Custom are derived entirely on the frontend from the inventory, so
//! no server-side config is needed for them.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

const CONFIG_PATH: &str = "/etc/wolfstack/control-panel.json";

// Inventory item shape (documented for reference; built as json! in
// the aggregator):
//   { node_id, node_hostname, cluster, kind: "docker"|"lxc"|"vm",
//     name, status, image, cpu_percent, memory_bytes, memory_limit_bytes }

/// Reference to an inventory item, used as group membership. Stable
/// enough to survive restarts; items that no longer exist in inventory
/// render as "stale" in the UI.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemberRef {
    pub node_id: String,
    pub kind: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Group {
    pub id: String,
    pub name: String,
    #[serde(default = "default_colour")]
    pub colour: String,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub members: Vec<MemberRef>,
}

fn default_colour() -> String { "#3b82f6".to_string() }

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ControlPanelConfig {
    #[serde(default)]
    pub groups: Vec<Group>,
}

impl ControlPanelConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = Path::new(CONFIG_PATH).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(CONFIG_PATH, json).map_err(|e| e.to_string())
    }
}

/// Process-wide lock so concurrent group edits don't lose data. The
/// config file is the source of truth but all mutating API handlers
/// take this lock across their read-modify-write cycle.
pub static CONFIG_LOCK: Mutex<()> = Mutex::new(());
