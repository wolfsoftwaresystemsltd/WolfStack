use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

/// Manages live log streams for provisioning tasks
pub struct ProvisionLogger {
    streams: Mutex<HashMap<String, broadcast::Sender<LogEntry>>>,
    history: Arc<Mutex<HashMap<String, Vec<LogEntry>>>>,
}

impl ProvisionLogger {
    pub fn new() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            history: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn create_stream(&self, task_id: &str) -> TaskLogger {
        let (tx, _) = broadcast::channel(256);
        self.streams.lock().await.insert(task_id.to_string(), tx.clone());
        self.history.lock().await.insert(task_id.to_string(), Vec::new());
        TaskLogger {
            task_id: task_id.to_string(),
            tx,
            history: self.history.clone(),
        }
    }

    pub async fn subscribe(&self, task_id: &str) -> Option<(Vec<LogEntry>, broadcast::Receiver<LogEntry>)> {
        let streams = self.streams.lock().await;
        let tx = streams.get(task_id)?;
        let rx = tx.subscribe();
        let hist = self.history.lock().await;
        let history = hist.get(task_id).cloned().unwrap_or_default();
        Some((history, rx))
    }

    pub async fn finish_stream(&self, task_id: &str) {
        self.streams.lock().await.remove(task_id);
    }
}

pub struct TaskLogger {
    task_id: String,
    tx: broadcast::Sender<LogEntry>,
    history: Arc<Mutex<HashMap<String, Vec<LogEntry>>>>,
}

impl TaskLogger {
    async fn log(&self, level: &str, msg: impl Into<String>) {
        let entry = LogEntry {
            timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
            level: level.to_string(),
            message: msg.into(),
        };
        self.history.lock().await
            .entry(self.task_id.clone())
            .or_default()
            .push(entry.clone());
        let _ = self.tx.send(entry);
    }

    pub async fn info(&self, msg: impl Into<String>) { self.log("info", msg).await; }
    pub async fn cmd(&self, msg: impl Into<String>) { self.log("cmd", msg).await; }
    pub async fn ok(&self, msg: impl Into<String>) { self.log("ok", msg).await; }
    pub async fn err(&self, msg: impl Into<String>) { self.log("err", msg).await; }
    pub async fn done(&self, msg: impl Into<String>) { self.log("done", msg).await; }
}
