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

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::{json, Value as JsonValue};
use crate::alert_fifo_item::AlertCategory;
use crate::alertable_entity::AlertEntity;

/// Represents a MAC address
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Mac([u8; 6]);

impl Mac {
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn to_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }

    pub fn get_device_type(&self) -> i32 {
        // TODO: Implement device type detection
        0
    }

    pub fn get_dhcp_name(&self) -> String {
        // TODO: Implement DHCP name retrieval
        String::new()
    }
}

/// Provides a way to send asynchronous alerts from Rust to Lua.
/// Alerts are processed by Lua in alert_utils.processStoreAlertFromQueue.
#[derive(Debug)]
pub struct AlertsQueue {
    /// Reference to the network interface
    iface: Arc<NetworkInterface>,
}

impl AlertsQueue {
    /// Creates a new AlertsQueue for the given network interface
    pub fn new(iface: Arc<NetworkInterface>) -> Self {
        Self { iface }
    }

    /// Pushes an alert in JSON format to the queue
    fn push_alert_json(
        &self,
        mut alert_data: JsonValue,
        alert_type: &str,
        subtype: Option<&str>,
        alert_category: AlertCategory,
    ) {
        // Add mandatory fields
        alert_data["ifid"] = json!(self.iface.get_id());
        alert_data["alert_id"] = json!(alert_type);
        alert_data["alert_category"] = json!(alert_category as u32);
        if let Some(subtype) = subtype {
            alert_data["subtype"] = json!(subtype);
        }
        alert_data["tstamp"] = json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );

        // Try to enqueue the alert
        if !self.iface.get_internal_alerts_queue().enqueue(alert_data) {
            self.iface.inc_num_dropped_alerts(AlertEntity::Custom);
        }
    }

    /// Pushes an alert for an IP address outside the DHCP range
    pub fn push_outside_dhcp_range_alert(
        &self,
        client_mac: &[u8; 6],
        sender_mac: &Mac,
        ip: u32,
        router_ip: u32,
        vlan_id: u16,
    ) {
        if self.iface.are_alerts_disabled() {
            return;
        }

        let client_mac_str = Mac::new(*client_mac).to_string();
        let sender_mac_str = sender_mac.to_string();
        let ip_str = format!("{}.{}.{}.{}", 
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF
        );
        let router_ip_str = format!("{}.{}.{}.{}", 
            (router_ip >> 24) & 0xFF,
            (router_ip >> 16) & 0xFF,
            (router_ip >> 8) & 0xFF,
            router_ip & 0xFF
        );

        log::info!(
            "IP not in DHCP range: {} (mac={}, sender={}, router={})",
            ip_str,
            client_mac_str,
            sender_mac_str,
            router_ip_str
        );

        let alert_data = json!({
            "client_mac": client_mac_str,
            "sender_mac": sender_mac_str,
            "client_ip": ip_str,
            "router_ip": router_ip_str,
            "vlan_id": vlan_id,
            "device_type": sender_mac.get_device_type(),
            "device_name": sender_mac.get_dhcp_name(),
        });

        self.push_alert_json(
            alert_data,
            "misconfigured_dhcp_range",
            None,
            AlertCategory::Network,
        );
    }

    /// Pushes an alert for a changed MAC-IP association
    pub fn push_mac_ip_association_changed_alert(
        &self,
        ip: u32,
        old_mac: &[u8; 6],
        new_mac: &[u8; 6],
        new_host_mac: &Mac,
    ) {
        if self.iface.are_alerts_disabled() {
            return;
        }

        let old_mac_str = Mac::new(*old_mac).to_string();
        let new_mac_str = Mac::new(*new_mac).to_string();
        let ip_str = format!("{}.{}.{}.{}", 
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF
        );

        log::info!(
            "IP {}: modified MAC association {} -> {}",
            ip_str,
            old_mac_str,
            new_mac_str
        );

        let alert_data = json!({
            "ip": ip_str,
            "old_mac": old_mac_str,
            "new_mac": new_mac_str,
            "device_type": new_host_mac.get_device_type(),
            "device_name": new_host_mac.get_dhcp_name(),
        });

        self.push_alert_json(
            alert_data,
            "mac_ip_association_change",
            None,
            AlertCategory::Network,
        );
    }

    /// Pushes an alert for a broadcast domain that is too large
    pub fn push_broadcast_domain_too_large_alert(
        &self,
        src_mac: &[u8; 6],
        dst_mac: &[u8; 6],
        spa: u32,
        tpa: u32,
        vlan_id: u16,
    ) {
        if self.iface.are_alerts_disabled() {
            return;
        }

        let alert_data = json!({
            "vlan_id": vlan_id,
            "src_mac": Mac::new(*src_mac).to_string(),
            "dst_mac": Mac::new(*dst_mac).to_string(),
            "spa": format!("{}.{}.{}.{}", 
                (spa >> 24) & 0xFF,
                (spa >> 16) & 0xFF,
                (spa >> 8) & 0xFF,
                spa & 0xFF
            ),
            "tpa": format!("{}.{}.{}.{}", 
                (tpa >> 24) & 0xFF,
                (tpa >> 16) & 0xFF,
                (tpa >> 8) & 0xFF,
                tpa & 0xFF
            ),
        });

        self.push_alert_json(
            alert_data,
            "broadcast_domain_too_large",
            None,
            AlertCategory::Network,
        );
    }

    /// Pushes a login trace alert
    pub fn push_login_trace(&self, user: &str, authorized: bool) {
        if self.iface.are_alerts_disabled() {
            return;
        }

        let alert_data = json!({
            "scope": "login",
            "user": user,
        });

        self.push_alert_json(
            alert_data,
            if authorized { "user_activity" } else { "login_failed" },
            None,
            AlertCategory::System,
        );
    }

    /// Pushes an alert for NFQ flush
    pub fn push_nfq_flushed_alert(&self, queue_len: i32, queue_len_pct: i32, queue_dropped: i32) {
        if self.iface.are_alerts_disabled() {
            return;
        }

        let alert_data = json!({
            "queue_len": queue_len,
            "queue_len_pct": queue_len_pct,
            "queue_dropped": queue_dropped,
        });

        self.push_alert_json(
            alert_data,
            "nfq_flushed",
            None,
            AlertCategory::System,
        );
    }

    /// Pushes an alert for cloud disconnection
    pub fn push_cloud_disconnection_alert(&self, descr: &str) {
        if self.iface.are_alerts_disabled() {
            return;
        }

        let alert_data = json!({
            "description": descr,
        });

        self.push_alert_json(
            alert_data,
            "cloud_disconnection",
            None,
            AlertCategory::System,
        );
    }

    /// Pushes an alert for cloud reconnection
    pub fn push_cloud_reconnection_alert(&self, descr: &str) {
        if self.iface.are_alerts_disabled() {
            return;
        }

        let alert_data = json!({
            "description": descr,
        });

        self.push_alert_json(
            alert_data,
            "cloud_reconnection",
            None,
            AlertCategory::System,
        );
    }

    /// Pushes an alert for SNMP trap
    pub fn push_snmp_trap_alert(&self, device_ip: &str, descr: &str) {
        if self.iface.are_alerts_disabled() {
            return;
        }

        let alert_data = json!({
            "device_ip": device_ip,
            "description": descr,
        });

        self.push_alert_json(
            alert_data,
            "snmp_trap",
            None,
            AlertCategory::Network,
        );
    }
}

/// NetworkInterface is a placeholder for the actual NetworkInterface implementation
pub struct NetworkInterface {
    // Add fields as needed
}

impl NetworkInterface {
    pub fn get_id(&self) -> u32 {
        // TODO: Implement
        0
    }

    pub fn are_alerts_disabled(&self) -> bool {
        // TODO: Implement
        false
    }

    pub fn get_internal_alerts_queue(&self) -> Arc<AlertsQueue> {
        // TODO: Implement
        unimplemented!()
    }

    pub fn inc_num_dropped_alerts(&self, _entity: AlertEntity) {
        // TODO: Implement
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address() {
        let mac = Mac::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_alerts_queue() {
        let iface = Arc::new(NetworkInterface {});
        let queue = AlertsQueue::new(Arc::clone(&iface));

        // Test login trace
        queue.push_login_trace("test_user", true);
        queue.push_login_trace("test_user", false);

        // Test SNMP trap
        queue.push_snmp_trap_alert("192.168.1.1", "Test trap");

        // Test cloud alerts
        queue.push_cloud_disconnection_alert("Lost connection");
        queue.push_cloud_reconnection_alert("Restored connection");
    }
}
