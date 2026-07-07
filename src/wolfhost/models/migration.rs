// Migration job — tracks one customer service being moved from a
// DirectAdmin source to a fresh WolfStack-managed LXC. The job is a
// linear state machine: each stage either succeeds and advances, or
// fails terminally with the error captured in `error`. Logs are
// timestamped strings so the admin can see which step blew up.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    /// Created, worker hasn't picked it up yet.
    Pending,
    /// Asked DA to create a SITE_BACKUP for the user.
    CreatingBackup,
    /// Polling DA's backup list waiting for the new file to appear.
    WaitingBackup,
    /// Provisioning a new LXC on a target node via WolfStack.
    ProvisioningLxc,
    /// LXC create returned; waiting for it to finish boot + reach
    /// reachable state.
    WaitingLxc,
    /// Downloading the backup tarball from DA to the wolfhost host.
    DownloadingBackup,
    /// Pushing the tarball into the new LXC over container exec.
    UploadingToLxc,
    /// Running `tar xzf` inside the LXC.
    Extracting,
    /// Importing SQL dumps into MariaDB inside the LXC.
    RestoringDatabases,
    /// Sanity-check the LXC before flipping the service record.
    /// Failures here are caught BEFORE the customer-facing flip, so
    /// the source DA keeps serving until the operator has fixed
    /// whatever went wrong (or chosen to retry / abandon).
    Verifying,
    /// Final clean-up: DA backup deletion, service record swap.
    Finalizing,
    Complete,
    Failed,
    /// Operator clicked Cancel before the worker reached a
    /// terminal state. The worker will refuse to advance further.
    Cancelled,
    /// Operator hit "Rollback" on a Complete migration. The service
    /// record was flipped back to DirectAdmin and (if it had been
    /// suspended at finalize) the DA user was unsuspended. The new
    /// LXC is left alive so the operator can inspect / clean up
    /// manually — auto-deleting it would discard restored data the
    /// operator might still want.
    RolledBack,
}

impl MigrationStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self,
            MigrationStatus::Complete
            | MigrationStatus::Failed
            | MigrationStatus::Cancelled
            | MigrationStatus::RolledBack)
    }

    /// Human-readable label for the admin UI status badge.
    pub fn label(&self) -> &'static str {
        match self {
            MigrationStatus::Pending             => "Pending",
            MigrationStatus::CreatingBackup      => "Creating backup",
            MigrationStatus::WaitingBackup       => "Waiting for backup",
            MigrationStatus::ProvisioningLxc     => "Provisioning LXC",
            MigrationStatus::WaitingLxc          => "Waiting for LXC",
            MigrationStatus::DownloadingBackup   => "Downloading backup",
            MigrationStatus::UploadingToLxc      => "Uploading to LXC",
            MigrationStatus::Extracting          => "Extracting",
            MigrationStatus::RestoringDatabases  => "Restoring databases",
            MigrationStatus::Verifying           => "Verifying",
            MigrationStatus::Finalizing          => "Finalising",
            MigrationStatus::Complete            => "Complete",
            MigrationStatus::Failed              => "Failed",
            MigrationStatus::Cancelled           => "Cancelled",
            MigrationStatus::RolledBack          => "Rolled back",
        }
    }

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationLogEntry {
    pub at: String,   // RFC3339
    pub kind: String, // "info" | "warn" | "error"
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Migration {
    pub id: String,
    pub service_id: String,
    pub customer_id: String,

    // Source (DA) snapshot taken at job creation. We snapshot rather
    // than re-resolving on every poll because the underlying service
    // record is going to be rewritten when we finalise — by then
    // `backend` is no longer DirectAdmin and the resolver would
    // refuse to look up the source.
    pub source_da_instance_id: String,
    pub source_da_username: String,
    pub source_domain: String,

    // Target LXC. `node_id` empty = auto-balance.
    #[serde(default)]
    pub target_node_id: String,
    #[serde(default)]
    pub target_template: String,
    #[serde(default)]
    pub target_memory_mb: u32,
    #[serde(default)]
    pub target_disk_gb: u32,
    #[serde(default)]
    pub target_cpu_cores: u32,

    pub status: MigrationStatus,
    #[serde(default)]
    pub log: Vec<MigrationLogEntry>,

    // Captured during the run.
    #[serde(default)]
    pub backup_filename: String,
    #[serde(default)]
    pub local_backup_path: String,
    #[serde(default)]
    pub new_container_name: String,
    #[serde(default)]
    pub new_container_node: String,

    pub started_at: String,
    #[serde(default)]
    pub completed_at: String,
    #[serde(default)]
    pub error: String,

    /// When set at job creation, the worker calls
    /// `da.suspend_user` after the Finalize step succeeds. Stops
    /// the customer from accidentally writing to the old DA
    /// account once they're on the new LXC.
    #[serde(default)]
    pub suspend_source_after: bool,
}

#[derive(Debug, Deserialize)]
pub struct StartMigrationRequest {
    pub service_id: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub template: String,
    #[serde(default)]
    pub memory_mb: u32,
    #[serde(default)]
    pub disk_gb: u32,
    #[serde(default)]
    pub cpu_cores: u32,
    #[serde(default)]
    pub suspend_source_after: bool,
}
