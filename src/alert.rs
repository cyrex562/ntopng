/*
 * (C) 2019-25 - ntop.org
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

use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

/// Represents different types of alerts that can be generated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertType {
    // Flow-based alerts
    FlowAnomaly,
    FlowFlood,
    TrafficVolume,
    
    // Scan-based alerts
    SYNScan,
    FINScan,
    RSTScan,
    HostScanner,
    ScanDetection,
    
    // Flood-based alerts
    SYNFlood,
    ICMPFlood,
    DNSFlood,
    SNMPFlood,
    
    // Contact-based alerts
    DNSServerContacts,
    NTPServerContacts,
    SMTPServerContacts,
    ServerPortsContacts,
    DomainNamesContacts,
    CountriesContacts,
    
    // Score-based alerts
    ScoreThreshold,
    ScoreAnomaly,
    
    // Security alerts
    DangerousHost,
    RemoteConnection,
    UnexpectedGateway,
    
    // Custom alerts
    CustomLuaScript,
    
    // Other
    Unknown
}

/// Represents an alert in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Timestamp when the alert was created
    pub tstamp: u64,
    
    /// Timestamp of the last update to this alert
    pub last_update: u64,
    
    /// Type of the alert
    pub alert_id: AlertType,
    
    /// Row ID used by engaged alert in the in-memory table
    pub rowid: u64,
    
    /// Port number associated with the alert
    pub port: u16,
    
    /// Alert score (0-100)
    pub score: u8,
    
    /// Whether the alert requires attention
    pub require_attention: bool,
    
    /// Alert subtype for more specific categorization
    pub subtype: String,
    
    /// JSON representation of additional alert data
    pub json: String,
    
    /// IP address associated with the alert
    pub ip: String,
    
    /// Name associated with the alert (e.g., hostname)
    pub name: String,
}

impl Default for Alert {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            tstamp: now,
            last_update: now,
            alert_id: AlertType::Unknown,
            rowid: 0,
            port: 0,
            score: 0,
            require_attention: false,
            subtype: String::new(),
            json: String::new(),
            ip: String::new(),
            name: String::new(),
        }
    }
}

impl Alert {
    /// Creates a new alert with the specified alert type
    pub fn new(alert_type: AlertType) -> Self {
        Self {
            alert_id: alert_type,
            ..Default::default()
        }
    }

    /// Updates the last_update timestamp to the current time
    pub fn touch(&mut self) {
        self.last_update = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Returns the age of the alert in seconds
    pub fn age(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.tstamp)
    }

    /// Returns the time since last update in seconds
    pub fn time_since_last_update(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.last_update)
    }

    /// Sets the alert data in JSON format
    pub fn set_json_data(&mut self, data: impl Into<String>) {
        self.json = data.into();
        self.touch();
    }

    /// Sets the IP address associated with the alert
    pub fn set_ip(&mut self, ip: impl Into<String>) {
        self.ip = ip.into();
        self.touch();
    }

    /// Sets the name associated with the alert
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
        self.touch();
    }

    /// Sets the subtype of the alert
    pub fn set_subtype(&mut self, subtype: impl Into<String>) {
        self.subtype = subtype.into();
        self.touch();
    }

    /// Sets the score of the alert (0-100)
    pub fn set_score(&mut self, score: u8) {
        self.score = score.min(100);
        self.touch();
    }

    /// Sets whether the alert requires attention
    pub fn set_require_attention(&mut self, require: bool) {
        self.require_attention = require;
        self.touch();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_alert_creation() {
        let alert = Alert::new(AlertType::FlowAnomaly);
        assert_eq!(alert.alert_id, AlertType::FlowAnomaly);
        assert_eq!(alert.score, 0);
        assert!(!alert.require_attention);
    }

    #[test]
    fn test_alert_update() {
        let mut alert = Alert::new(AlertType::SYNScan);
        let original_time = alert.last_update;
        
        thread::sleep(Duration::from_secs(1));
        alert.set_score(50);
        
        assert!(alert.last_update > original_time);
        assert_eq!(alert.score, 50);
    }

    #[test]
    fn test_alert_age() {
        let alert = Alert::new(AlertType::DNSFlood);
        thread::sleep(Duration::from_secs(1));
        assert!(alert.age() >= 1);
    }

    #[test]
    fn test_alert_json() {
        let mut alert = Alert::new(AlertType::CustomLuaScript);
        alert.set_json_data(r#"{"key": "value"}"#);
        assert_eq!(alert.json, r#"{"key": "value"}"#);
    }

    #[test]
    fn test_alert_score_bounds() {
        let mut alert = Alert::new(AlertType::ScoreThreshold);
        alert.set_score(255); // Should be capped at 100
        assert_eq!(alert.score, 100);
    }
}
