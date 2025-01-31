/*
 * (C) 2021-25 - ntop.org
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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use mlua::prelude::*;
use crate::address_tree::AddressTree;
use crate::alert::AlertType;

/// Represents the type of entity that can be alerted
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertEntity {
    Host,
    Network,
    Interface,
    Flow,
    System,
    Custom,
}

/// Represents the severity level of an alert
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AlertLevel {
    Info,
    Warning,
    Error,
    Critical,
}

/// Represents the role of an alert
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertRole {
    Client,
    Server,
    Both,
}

/// Counter for grouped alerts
#[derive(Debug, Default)]
pub struct GroupedAlertsCounters {
    pub info: u32,
    pub warning: u32,
    pub error: u32,
    pub critical: u32,
}

/// Represents an entity that can receive alerts
pub struct AlertableEntity {
    /// Type of the entity
    entity_type: AlertEntity,
    
    /// Value identifying the entity (e.g., IP address, network name)
    entity_val: String,
    
    /// Reference to the network interface
    alert_iface: Arc<NetworkInterface>,
    
    /// Number of currently engaged alerts
    num_engaged_alerts: u32,
    
    /// Lock for handling concurrent access from the GUI
    engaged_alerts_lock: RwLock<()>,
}

impl AlertableEntity {
    /// Creates a new AlertableEntity
    pub fn new(iface: Arc<NetworkInterface>, entity: AlertEntity) -> Self {
        Self {
            entity_type: entity,
            entity_val: String::new(),
            alert_iface: iface,
            num_engaged_alerts: 0,
            engaged_alerts_lock: RwLock::new(()),
        }
    }

    /// Gets a reference to the alert interface
    pub fn get_alert_interface(&self) -> &Arc<NetworkInterface> {
        &self.alert_iface
    }

    /// Sets the entity value
    pub fn set_entity_value(&mut self, val: impl Into<String>) {
        self.entity_val = val.into();
    }

    /// Gets the entity value
    pub fn get_entity_value(&self) -> &str {
        &self.entity_val
    }

    /// Gets the entity type
    pub fn get_entity_type(&self) -> AlertEntity {
        self.entity_type
    }

    /// Gets the number of engaged alerts
    pub fn get_num_engaged_alerts(&self) -> u32 {
        self.num_engaged_alerts
    }

    /// Increases the number of engaged alerts
    fn inc_num_alerts_engaged(&mut self, alert_severity: AlertLevel) {
        self.alert_iface.inc_num_alerts_engaged(self.entity_type, alert_severity);
        self.num_engaged_alerts += 1;
    }

    /// Decreases the number of engaged alerts
    fn dec_num_alerts_engaged(&mut self, alert_severity: AlertLevel) {
        self.alert_iface.dec_num_alerts_engaged(self.entity_type, alert_severity);
        self.num_engaged_alerts = self.num_engaged_alerts.saturating_sub(1);
    }

    /// Parses an IP address from an entity value string
    pub fn parse_entity_value_ip(alert_entity_value: &str) -> Option<IpAddr> {
        // Split off VLAN if present
        let ip_str = alert_entity_value.split('@').next()?;
        
        // Split off subnet if present
        let ip_str = ip_str.split('/').next()?;
        
        // Try parsing as IPv6 first, then IPv4
        if ip_str.contains(':') {
            if let Ok(addr) = ip_str.parse::<Ipv6Addr>() {
                Some(IpAddr::V6(addr))
            } else {
                None
            }
        } else {
            if let Ok(addr) = ip_str.parse::<Ipv4Addr>() {
                Some(IpAddr::V4(addr))
            } else {
                None
            }
        }
    }

    /// Checks if the entity matches the allowed networks
    pub fn matches_allowed_networks(&self, allowed_nets: Option<&AddressTree>) -> bool {
        let allowed_nets = match allowed_nets {
            Some(nets) => nets,
            None => return true,
        };

        let ip = match Self::parse_entity_value_ip(&self.entity_val) {
            Some(ip) => ip,
            None => return false,
        };

        let netbits = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        allowed_nets.match_ip(&ip, netbits)
    }

    /// Counts alerts by severity
    pub fn count_alerts(&self, _counters: &mut GroupedAlertsCounters) {
        // To be implemented by derived types
    }

    /// Gets alerts filtered by various criteria
    pub fn get_alerts(
        &self,
        _lua: &Lua,
        _periodicity: ScriptPeriodicity,
        _type_filter: Option<AlertType>,
        _severity_filter: Option<AlertLevel>,
        _role_filter: Option<AlertRole>,
        _idx: &mut u32,
    ) -> LuaResult<()> {
        // To be implemented by derived types
        Ok(())
    }
}

/// Represents the periodicity of alert scripts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptPeriodicity {
    Minute,
    Hour,
    Day,
}

/// NetworkInterface is a placeholder for the actual NetworkInterface implementation
pub struct NetworkInterface {
    // Add fields as needed
}

impl NetworkInterface {
    pub fn inc_num_alerts_engaged(&self, _entity: AlertEntity, _severity: AlertLevel) {
        // To be implemented
    }

    pub fn dec_num_alerts_engaged(&self, _entity: AlertEntity, _severity: AlertLevel) {
        // To be implemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_entity_value_ip() {
        // Test IPv4
        let ip4 = AlertableEntity::parse_entity_value_ip("192.168.1.1");
        assert_eq!(ip4, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Test IPv4 with VLAN
        let ip4_vlan = AlertableEntity::parse_entity_value_ip("192.168.1.1@100");
        assert_eq!(ip4_vlan, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Test IPv4 with subnet
        let ip4_subnet = AlertableEntity::parse_entity_value_ip("192.168.1.0/24");
        assert_eq!(ip4_subnet, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))));

        // Test IPv6
        let ip6 = AlertableEntity::parse_entity_value_ip("2001:db8::1");
        assert_eq!(ip6, Some(IpAddr::V6(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        )));

        // Test invalid IP
        let invalid = AlertableEntity::parse_entity_value_ip("invalid");
        assert_eq!(invalid, None);
    }

    #[test]
    fn test_alertable_entity() {
        let iface = Arc::new(NetworkInterface {});
        let mut entity = AlertableEntity::new(iface, AlertEntity::Host);
        
        entity.set_entity_value("192.168.1.1");
        assert_eq!(entity.get_entity_value(), "192.168.1.1");
        assert_eq!(entity.get_entity_type(), AlertEntity::Host);
        assert_eq!(entity.get_num_engaged_alerts(), 0);
    }
}
