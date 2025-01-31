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

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct FlowsHostInfo {
    ip_addr: IpAddr,
    hostname: Option<String>,
    vlan_id: u16,
}

impl FlowsHostInfo {
    pub fn new(ip: IpAddr, hostname: Option<String>, vlan_id: u16) -> Self {
        Self {
            ip_addr: ip,
            hostname,
            vlan_id,
        }
    }

    pub fn get_ip(&self) -> IpAddr {
        self.ip_addr
    }

    pub fn get_hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    pub fn get_vlan_id(&self) -> u16 {
        self.vlan_id
    }

    pub fn get_ip_hex(&self) -> String {
        match self.ip_addr {
            IpAddr::V4(ip) => format!("{:08X}", u32::from_be_bytes(ip.octets())),
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                let mut hex = String::with_capacity(32);
                for byte in &octets {
                    hex.push_str(&format!("{:02X}", byte));
                }
                hex
            }
        }
    }
}

#[derive(Debug)]
pub struct AggregatedFlowsStats {
    clients: HashSet<String>,
    servers: HashSet<String>,
    num_flows: u32,
    tot_score: u32,
    tot_sent: u64,
    tot_rcvd: u64,
    l4_proto: u8,
    client: Option<Arc<FlowsHostInfo>>,
    server: Option<Arc<FlowsHostInfo>>,
    vlan_id: u16,
    srv_port: u16,
    proto_name: Option<String>,
    info_key: Option<String>,
    key: u64,
    proto_key: u64,
    is_not_guessed: bool,
    flow_device_ip: u32,
}

impl AggregatedFlowsStats {
    pub fn new(client: Option<&IpAddr>, server: Option<&IpAddr>, l4_proto: u8, 
               bytes_sent: u64, bytes_rcvd: u64, score: u32) -> Self {
        let mut stats = Self {
            clients: HashSet::new(),
            servers: HashSet::new(),
            num_flows: 0,
            tot_score: 0,
            tot_sent: 0,
            tot_rcvd: 0,
            l4_proto,
            client: None,
            server: None,
            vlan_id: 0,
            srv_port: 0,
            proto_name: None,
            info_key: None,
            key: 0,
            proto_key: 0,
            is_not_guessed: false,
            flow_device_ip: 0,
        };

        stats.inc_flow_stats(client, server, bytes_sent, bytes_rcvd, score);
        stats
    }

    pub fn inc_flow_stats(&mut self, client: Option<&IpAddr>, server: Option<&IpAddr>,
                         bytes_sent: u64, bytes_rcvd: u64, score: u32) {
        if let Some(client_ip) = client {
            self.clients.insert(Self::ip_to_hex(client_ip));
        }
        
        if let Some(server_ip) = server {
            self.servers.insert(Self::ip_to_hex(server_ip));
        }

        self.num_flows += 1;
        self.tot_sent += bytes_sent;
        self.tot_rcvd += bytes_rcvd;
        self.tot_score += score;
    }

    fn ip_to_hex(ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ip) => format!("{:08X}", u32::from_be_bytes(ip.octets())),
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                let mut hex = String::with_capacity(32);
                for byte in &octets {
                    hex.push_str(&format!("{:02X}", byte));
                }
                hex
            }
        }
    }

    // Getters
    pub fn get_l4_protocol(&self) -> u8 { self.l4_proto }
    pub fn get_srv_port(&self) -> u16 { self.srv_port }
    pub fn get_vlan_id(&self) -> u16 { self.vlan_id }
    pub fn get_cli_vlan_id(&self) -> u16 { 
        self.client.as_ref().map_or(0, |c| c.get_vlan_id())
    }
    pub fn get_srv_vlan_id(&self) -> u16 { 
        self.server.as_ref().map_or(0, |s| s.get_vlan_id())
    }
    pub fn get_num_clients(&self) -> u32 { self.clients.len() as u32 }
    pub fn get_num_servers(&self) -> u32 { self.servers.len() as u32 }
    pub fn get_num_flows(&self) -> u32 { self.num_flows }
    pub fn get_total_score(&self) -> u32 { self.tot_score }
    pub fn get_key(&self) -> u64 { self.key }
    pub fn get_proto_key(&self) -> u64 { self.proto_key }
    pub fn get_total_sent(&self) -> u64 { self.tot_sent }
    pub fn get_total_rcvd(&self) -> u64 { self.tot_rcvd }
    pub fn get_proto_name(&self) -> &str { 
        self.proto_name.as_deref().unwrap_or("")
    }
    pub fn get_info_key(&self) -> &str { 
        self.info_key.as_deref().unwrap_or("")
    }

    pub fn get_cli_ip(&self) -> Option<IpAddr> {
        self.client.as_ref().map(|c| c.get_ip())
    }

    pub fn get_srv_ip(&self) -> Option<IpAddr> {
        self.server.as_ref().map(|s| s.get_ip())
    }

    pub fn get_cli_name(&self) -> Option<&str> {
        self.client.as_ref().and_then(|c| c.get_hostname())
    }

    pub fn get_srv_name(&self) -> Option<&str> {
        self.server.as_ref().and_then(|s| s.get_hostname())
    }

    pub fn get_cli_ip_hex(&self) -> Option<String> {
        self.client.as_ref().map(|c| c.get_ip_hex())
    }

    pub fn get_srv_ip_hex(&self) -> Option<String> {
        self.server.as_ref().map(|c| c.get_ip_hex())
    }

    pub fn get_flow_device_ip(&self) -> Option<String> {
        if self.flow_device_ip != 0 {
            Some(format!("{}.{}.{}.{}", 
                (self.flow_device_ip >> 24) & 0xFF,
                (self.flow_device_ip >> 16) & 0xFF,
                (self.flow_device_ip >> 8) & 0xFF,
                self.flow_device_ip & 0xFF))
        } else {
            None
        }
    }

    pub fn is_not_guessed(&self) -> bool { 
        self.is_not_guessed 
    }

    // Setters
    pub fn set_proto_name(&mut self, name: String) {
        self.proto_name = Some(name);
    }

    pub fn set_info_key(&mut self, key: String) {
        self.info_key = Some(key);
    }

    pub fn set_client(&mut self, ip: IpAddr, hostname: Option<String>) {
        self.client = Some(Arc::new(FlowsHostInfo::new(ip, hostname, self.vlan_id)));
    }

    pub fn set_server(&mut self, ip: IpAddr, hostname: Option<String>) {
        self.server = Some(Arc::new(FlowsHostInfo::new(ip, hostname, self.vlan_id)));
    }

    pub fn set_vlan_id(&mut self, id: u16) {
        self.vlan_id = id;
    }

    pub fn set_flow_device_ip(&mut self, ip: u32) {
        self.flow_device_ip = ip;
    }
}

#[derive(Debug, Default)]
pub struct AggregatedStats {
    count: HashMap<u64, Arc<AggregatedFlowsStats>>,
    info_count: HashMap<String, Arc<AggregatedFlowsStats>>,
    ip_addr: Option<IpAddr>,
    vlan_id: u16,
    flow_device_ip: u32,
    in_if_index: u32,
    out_if_index: u32,
}

impl AggregatedStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_flow_stats(&mut self, key: u64, info_key: Option<String>, stats: AggregatedFlowsStats) {
        let stats = Arc::new(stats);
        self.count.insert(key, Arc::clone(&stats));
        if let Some(info_key) = info_key {
            self.info_count.insert(info_key, stats);
        }
    }

    pub fn get_flow_stats(&self, key: u64) -> Option<Arc<AggregatedFlowsStats>> {
        self.count.get(&key).cloned()
    }

    pub fn get_flow_stats_by_info(&self, info_key: &str) -> Option<Arc<AggregatedFlowsStats>> {
        self.info_count.get(info_key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_flows_host_info() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host = FlowsHostInfo::new(ip, Some("localhost".to_string()), 1);

        assert_eq!(host.get_ip(), ip);
        assert_eq!(host.get_hostname(), Some("localhost"));
        assert_eq!(host.get_vlan_id(), 1);
        assert_eq!(host.get_ip_hex(), "C0A80101");
    }

    #[test]
    fn test_aggregated_flows_stats() {
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let server_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        
        let mut stats = AggregatedFlowsStats::new(
            Some(&client_ip),
            Some(&server_ip),
            6, // TCP
            1000,
            2000,
            10
        );

        assert_eq!(stats.get_num_flows(), 1);
        assert_eq!(stats.get_total_sent(), 1000);
        assert_eq!(stats.get_total_rcvd(), 2000);
        assert_eq!(stats.get_total_score(), 10);
        assert_eq!(stats.get_num_clients(), 1);
        assert_eq!(stats.get_num_servers(), 1);
    }

    #[test]
    fn test_aggregated_stats() {
        let mut stats = AggregatedStats::new();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let server_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        
        let flow_stats = AggregatedFlowsStats::new(
            Some(&client_ip),
            Some(&server_ip),
            6,
            1000,
            2000,
            10
        );

        stats.add_flow_stats(1, Some("test".to_string()), flow_stats);
        
        assert!(stats.get_flow_stats(1).is_some());
        assert!(stats.get_flow_stats_by_info("test").is_some());
    }
}
