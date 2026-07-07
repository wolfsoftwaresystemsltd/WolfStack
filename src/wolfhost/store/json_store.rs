use serde::{de::DeserializeOwned, Serialize};
use sqlx::mysql::MySqlPool;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct JsonStore {
    data_dir: PathBuf,
}

impl JsonStore {
    pub fn new(data_dir: &Path) -> Self {
        std::fs::create_dir_all(data_dir).ok();
        Self {
            data_dir: data_dir.to_path_buf(),
        }
    }

    fn file_path(&self, collection: &str) -> PathBuf {
        self.data_dir.join(format!("{}.json", collection))
    }

    pub fn load<T: DeserializeOwned + Default>(&self, collection: &str) -> T {
        let path = self.file_path(collection);
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => T::default(),
        }
    }

    pub fn save<T: Serialize>(&self, collection: &str, data: &T) -> Result<(), String> {
        let path = self.file_path(collection);
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| format!("Serialize error: {}", e))?;

        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &json)
            .map_err(|e| format!("Write error: {}", e))?;
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| format!("Rename error: {}", e))?;
        Ok(())
    }

    pub fn load_vec<T: DeserializeOwned>(&self, collection: &str) -> Vec<T> {
        self.load::<Vec<T>>(collection)
    }

    pub fn save_vec<T: Serialize>(&self, collection: &str, data: &[T]) -> Result<(), String> {
        self.save(collection, &data)
    }
}

/// Storage backend — either JSON files or MariaDB
#[derive(Clone)]
pub enum StorageBackend {
    Json(JsonStore),
    MySql(Arc<MySqlPool>),
}

/// Thread-safe data store with in-memory cache backed by JSON or MariaDB
pub struct DataStore<T: Clone + Send + Sync> {
    backend: StorageBackend,
    collection: String,
    /// DB table name (may differ from collection, e.g. "databases" -> "customer_databases")
    table_name: String,
    cache: Arc<RwLock<Vec<T>>>,
    /// Function to extract the id from an item (for DB upsert)
    id_extractor: fn(&T) -> String,
}

impl<T: Clone + Send + Sync + Serialize + DeserializeOwned + 'static> DataStore<T> {
    /// Create a DataStore with JSON backend
    pub fn json(store: JsonStore, collection: &str, id_fn: fn(&T) -> String) -> Self {
        let items: Vec<T> = store.load_vec(collection);
        Self {
            backend: StorageBackend::Json(store),
            collection: collection.to_string(),
            table_name: collection.to_string(),
            cache: Arc::new(RwLock::new(items)),
            id_extractor: id_fn,
        }
    }

    /// Create a DataStore with MariaDB backend (loads initial data from DB)
    pub async fn mysql(pool: Arc<MySqlPool>, collection: &str, table: &str, id_fn: fn(&T) -> String) -> Self {
        let items = super::mysql_store::load_all::<T>(&pool, table).await.unwrap_or_else(|e| {
            log::error!("Failed to load '{}' from MariaDB: {}", table, e);
            Vec::new()
        });
        log::info!("Loaded {} items from MariaDB table '{}'", items.len(), table);
        Self {
            backend: StorageBackend::MySql(pool),
            collection: collection.to_string(),
            table_name: table.to_string(),
            cache: Arc::new(RwLock::new(items)),
            id_extractor: id_fn,
        }
    }

    pub async fn list(&self) -> Vec<T> {
        self.cache.read().await.clone()
    }

    pub async fn update_with<F>(&self, f: F) -> Result<(), String>
    where
        F: FnOnce(&mut Vec<T>),
    {
        let mut items = self.cache.write().await;
        f(&mut items);
        self.persist(&items).await?;
        Ok(())
    }

    async fn persist(&self, items: &[T]) -> Result<(), String> {
        match &self.backend {
            StorageBackend::Json(store) => {
                store.save_vec(&self.collection, items)
            }
            StorageBackend::MySql(pool) => {
                super::mysql_store::save_all(pool, &self.table_name, items, self.id_extractor).await
            }
        }
    }
}
