/*
 * (C) 2013-25 - ntop.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

use std::error::Error;
use mlua::{Lua, Table, Value};
use serde::{Serialize, Deserialize};
use std::sync::Arc;

/// Result type for AlertStore operations
pub type AlertStoreResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Represents a query result row from the alert store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    /// Timestamp of the alert
    pub timestamp: i64,
    /// Type of the alert
    pub alert_type: String,
    /// Severity level of the alert
    pub severity: String,
    /// Source of the alert
    pub source: String,
    /// Additional metadata as JSON
    pub metadata: serde_json::Value,
}

/// Trait defining the interface for alert storage implementations
pub trait AlertStore: Send + Sync {
    /// Executes a query against the alert store
    /// 
    /// # Arguments
    /// * `lua` - Lua state for returning results
    /// * `query` - Query string to execute
    /// * `limit_rows` - Whether to limit the number of returned rows
    /// 
    /// # Returns
    /// * `AlertStoreResult<bool>` - True if query was successful, false otherwise
    fn query(&self, lua: &Lua, query: &str, limit_rows: bool) -> AlertStoreResult<bool>;

    /// Stores a new alert in the store
    /// 
    /// # Arguments
    /// * `alert` - Alert record to store
    /// 
    /// # Returns
    /// * `AlertStoreResult<()>` - Success or error
    fn store_alert(&self, alert: AlertRecord) -> AlertStoreResult<()>;

    /// Retrieves alerts within a time range
    /// 
    /// # Arguments
    /// * `start_time` - Start of time range (Unix timestamp)
    /// * `end_time` - End of time range (Unix timestamp)
    /// 
    /// # Returns
    /// * `AlertStoreResult<Vec<AlertRecord>>` - Vector of matching alerts
    fn get_alerts_in_range(&self, start_time: i64, end_time: i64) -> AlertStoreResult<Vec<AlertRecord>>;

    /// Retrieves alerts by severity
    /// 
    /// # Arguments
    /// * `severity` - Severity level to filter by
    /// * `limit` - Maximum number of alerts to return
    /// 
    /// # Returns
    /// * `AlertStoreResult<Vec<AlertRecord>>` - Vector of matching alerts
    fn get_alerts_by_severity(&self, severity: &str, limit: usize) -> AlertStoreResult<Vec<AlertRecord>>;

    /// Retrieves alerts by type
    /// 
    /// # Arguments
    /// * `alert_type` - Type of alerts to retrieve
    /// * `limit` - Maximum number of alerts to return
    /// 
    /// # Returns
    /// * `AlertStoreResult<Vec<AlertRecord>>` - Vector of matching alerts
    fn get_alerts_by_type(&self, alert_type: &str, limit: usize) -> AlertStoreResult<Vec<AlertRecord>>;

    /// Counts alerts by severity
    /// 
    /// # Returns
    /// * `AlertStoreResult<std::collections::HashMap<String, usize>>` - Map of severity to count
    fn count_alerts_by_severity(&self) -> AlertStoreResult<std::collections::HashMap<String, usize>>;

    /// Deletes alerts older than the specified timestamp
    /// 
    /// # Arguments
    /// * `older_than` - Timestamp threshold (Unix timestamp)
    /// 
    /// # Returns
    /// * `AlertStoreResult<usize>` - Number of alerts deleted
    fn delete_old_alerts(&self, older_than: i64) -> AlertStoreResult<usize>;
}

/// In-memory implementation of AlertStore
#[derive(Debug, Default)]
pub struct MemoryAlertStore {
    alerts: Arc<parking_lot::RwLock<Vec<AlertRecord>>>,
}

impl MemoryAlertStore {
    /// Creates a new MemoryAlertStore
    pub fn new() -> Self {
        Self {
            alerts: Arc::new(parking_lot::RwLock::new(Vec::new())),
        }
    }

    /// Converts AlertRecord to Lua table
    fn alert_to_lua_table(&self, lua: &Lua, alert: &AlertRecord) -> mlua::Result<Table> {
        let table = lua.create_table()?;
        table.set("timestamp", alert.timestamp)?;
        table.set("alert_type", alert.alert_type.clone())?;
        table.set("severity", alert.severity.clone())?;
        table.set("source", alert.source.clone())?;
        
        // Convert metadata JSON to Lua table
        let metadata_str = serde_json::to_string(&alert.metadata)
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        let metadata_value: Value = lua.load(&metadata_str).eval()?;
        table.set("metadata", metadata_value)?;
        
        Ok(table)
    }
}

impl AlertStore for MemoryAlertStore {
    fn query(&self, lua: &Lua, query: &str, limit_rows: bool) -> AlertStoreResult<bool> {
        let alerts = self.alerts.read();
        let mut results = Vec::new();

        // Simple query parsing (could be expanded)
        let query = query.to_lowercase();
        for alert in alerts.iter() {
            if alert.alert_type.to_lowercase().contains(&query) ||
               alert.severity.to_lowercase().contains(&query) ||
               alert.source.to_lowercase().contains(&query) {
                results.push(alert);
            }

            if limit_rows && results.len() >= 1000 {
                break;
            }
        }

        // Create Lua table with results
        let results_table = lua.create_table()?;
        for (i, alert) in results.iter().enumerate() {
            let alert_table = self.alert_to_lua_table(lua, alert)?;
            results_table.set(i + 1, alert_table)?;
        }

        // Set global variable with results
        lua.globals().set("query_results", results_table)?;
        
        Ok(!results.is_empty())
    }

    fn store_alert(&self, alert: AlertRecord) -> AlertStoreResult<()> {
        let mut alerts = self.alerts.write();
        alerts.push(alert);
        Ok(())
    }

    fn get_alerts_in_range(&self, start_time: i64, end_time: i64) -> AlertStoreResult<Vec<AlertRecord>> {
        let alerts = self.alerts.read();
        Ok(alerts
            .iter()
            .filter(|a| a.timestamp >= start_time && a.timestamp <= end_time)
            .cloned()
            .collect())
    }

    fn get_alerts_by_severity(&self, severity: &str, limit: usize) -> AlertStoreResult<Vec<AlertRecord>> {
        let alerts = self.alerts.read();
        Ok(alerts
            .iter()
            .filter(|a| a.severity == severity)
            .take(limit)
            .cloned()
            .collect())
    }

    fn get_alerts_by_type(&self, alert_type: &str, limit: usize) -> AlertStoreResult<Vec<AlertRecord>> {
        let alerts = self.alerts.read();
        Ok(alerts
            .iter()
            .filter(|a| a.alert_type == alert_type)
            .take(limit)
            .cloned()
            .collect())
    }

    fn count_alerts_by_severity(&self) -> AlertStoreResult<std::collections::HashMap<String, usize>> {
        let alerts = self.alerts.read();
        let mut counts = std::collections::HashMap::new();
        for alert in alerts.iter() {
            *counts.entry(alert.severity.clone()).or_insert(0) += 1;
        }
        Ok(counts)
    }

    fn delete_old_alerts(&self, older_than: i64) -> AlertStoreResult<usize> {
        let mut alerts = self.alerts.write();
        let initial_len = alerts.len();
        alerts.retain(|a| a.timestamp > older_than);
        Ok(initial_len - alerts.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_alert(alert_type: &str, severity: &str) -> AlertRecord {
        AlertRecord {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            alert_type: alert_type.to_string(),
            severity: severity.to_string(),
            source: "test".to_string(),
            metadata: serde_json::json!({"test": "data"}),
        }
    }

    #[test]
    fn test_memory_store_basic_operations() {
        let store = MemoryAlertStore::new();
        
        // Store some test alerts
        let alert1 = create_test_alert("security", "high");
        let alert2 = create_test_alert("performance", "medium");
        
        store.store_alert(alert1.clone()).unwrap();
        store.store_alert(alert2.clone()).unwrap();

        // Test retrieving by severity
        let high_alerts = store.get_alerts_by_severity("high", 10).unwrap();
        assert_eq!(high_alerts.len(), 1);
        assert_eq!(high_alerts[0].alert_type, "security");

        // Test retrieving by type
        let security_alerts = store.get_alerts_by_type("security", 10).unwrap();
        assert_eq!(security_alerts.len(), 1);
        assert_eq!(security_alerts[0].severity, "high");

        // Test counting by severity
        let counts = store.count_alerts_by_severity().unwrap();
        assert_eq!(counts.get("high").unwrap(), &1);
        assert_eq!(counts.get("medium").unwrap(), &1);
    }

    #[test]
    fn test_alert_deletion() {
        let store = MemoryAlertStore::new();
        let alert = create_test_alert("test", "low");
        store.store_alert(alert).unwrap();

        // Delete future alerts (should delete nothing)
        let deleted = store.delete_old_alerts(i64::MAX).unwrap();
        assert_eq!(deleted, 1);

        // Verify store is empty
        let all_alerts = store.get_alerts_in_range(0, i64::MAX).unwrap();
        assert!(all_alerts.is_empty());
    }

    #[test]
    fn test_lua_integration() -> AlertStoreResult<()> {
        let store = MemoryAlertStore::new();
        let lua = Lua::new();

        // Store a test alert
        let alert = create_test_alert("test_lua", "medium");
        store.store_alert(alert)?;

        // Query for the alert
        let found = store.query(&lua, "test_lua", true)?;
        assert!(found);

        // Verify result in Lua
        let results: Table = lua.globals().get("query_results")?;
        assert_eq!(results.len()?, 1);

        Ok(())
    }
}
