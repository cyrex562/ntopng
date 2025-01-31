/*
 * (C) 2014-25 - ntop.org
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

use serde::{Serialize, Deserialize};
use crate::alertable_entity::AlertEntity;
use crate::alertable_entity::AlertLevel;

/// Categories of alerts that can be generated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertCategory {
    /// Network-related alerts
    Network,
    /// Security-related alerts
    Security,
    /// System-related alerts
    System,
    /// Performance-related alerts
    Performance,
    /// Configuration-related alerts
    Configuration,
    /// Custom alerts (e.g., from Lua scripts)
    Custom,
    /// Other/uncategorized alerts
    Other,
}

impl Default for AlertCategory {
    fn default() -> Self {
        Self::Other
    }
}

/// Host-specific alert information
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct HostInfo {
    /// Host pool identifier
    pub host_pool: u16,
}

/// Flow-specific alert information
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FlowInfo {
    /// Client host pool identifier
    pub cli_host_pool: u16,
    /// Server host pool identifier
    pub srv_host_pool: u16,
}

/// Represents an item in the alert FIFO queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertFifoItem {
    /// Type of entity that generated the alert
    pub alert_entity: AlertEntity,
    
    /// Severity level of the alert
    pub alert_severity: AlertLevel,
    
    /// Category of the alert
    pub alert_category: AlertCategory,
    
    /// Alert details in JSON format
    pub alert: String,
    
    /// Alert score (0-100)
    pub score: u32,
    
    /// Unique identifier for the alert
    pub alert_id: u16,
    
    /// Host-specific information
    pub host: HostInfo,
    
    /// Flow-specific information
    pub flow: FlowInfo,
}

impl Default for AlertFifoItem {
    fn default() -> Self {
        Self {
            alert_entity: AlertEntity::Custom, // Equivalent to alert_entity_other
            alert_severity: AlertLevel::Info,  // Equivalent to alert_level_none
            alert_category: AlertCategory::Other,
            alert: String::new(),
            score: 0,
            alert_id: 0,
            host: HostInfo::default(),
            flow: FlowInfo::default(),
        }
    }
}

impl AlertFifoItem {
    /// Creates a new AlertFifoItem with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new AlertFifoItem by copying values from another item
    pub fn from(item: &AlertFifoItem) -> Self {
        Self {
            alert_entity: item.alert_entity,
            alert_severity: item.alert_severity,
            alert_category: item.alert_category,
            alert: item.alert.clone(),
            score: item.score,
            alert_id: item.alert_id,
            host: item.host,
            flow: item.flow,
        }
    }

    /// Sets the alert JSON content
    pub fn set_alert(&mut self, alert: impl Into<String>) {
        self.alert = alert.into();
    }

    /// Sets the alert score
    pub fn set_score(&mut self, score: u32) {
        self.score = score;
    }

    /// Sets the alert ID
    pub fn set_alert_id(&mut self, id: u16) {
        self.alert_id = id;
    }

    /// Sets the host pool
    pub fn set_host_pool(&mut self, pool: u16) {
        self.host.host_pool = pool;
    }

    /// Sets the client host pool for flow alerts
    pub fn set_cli_host_pool(&mut self, pool: u16) {
        self.flow.cli_host_pool = pool;
    }

    /// Sets the server host pool for flow alerts
    pub fn set_srv_host_pool(&mut self, pool: u16) {
        self.flow.srv_host_pool = pool;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_fifo_item_default() {
        let item = AlertFifoItem::default();
        assert_eq!(item.alert_entity, AlertEntity::Custom);
        assert_eq!(item.alert_severity, AlertLevel::Info);
        assert_eq!(item.alert_category, AlertCategory::Other);
        assert_eq!(item.score, 0);
        assert_eq!(item.alert_id, 0);
        assert_eq!(item.host.host_pool, 0);
        assert_eq!(item.flow.cli_host_pool, 0);
        assert_eq!(item.flow.srv_host_pool, 0);
    }

    #[test]
    fn test_alert_fifo_item_from() {
        let mut original = AlertFifoItem::default();
        original.alert_category = AlertCategory::Security;
        original.score = 50;
        original.alert_id = 123;
        original.set_alert(r#"{"key": "value"}"#);

        let copied = AlertFifoItem::from(&original);
        assert_eq!(copied.alert_category, AlertCategory::Security);
        assert_eq!(copied.score, 50);
        assert_eq!(copied.alert_id, 123);
        assert_eq!(copied.alert, r#"{"key": "value"}"#);
    }

    #[test]
    fn test_alert_fifo_item_setters() {
        let mut item = AlertFifoItem::new();
        
        item.set_score(75);
        assert_eq!(item.score, 75);

        item.set_alert_id(456);
        assert_eq!(item.alert_id, 456);

        item.set_host_pool(10);
        assert_eq!(item.host.host_pool, 10);

        item.set_cli_host_pool(20);
        assert_eq!(item.flow.cli_host_pool, 20);

        item.set_srv_host_pool(30);
        assert_eq!(item.flow.srv_host_pool, 30);
    }
}
