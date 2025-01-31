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

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use mlua::{Lua, Table, Value};

/// Level of details for data serialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailsLevel {
    /// Basic information
    Low,
    /// Standard information
    Medium,
    /// High level of detail
    High,
    /// Maximum level of detail
    Higher,
}

/// Statistics for network traffic
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficStats {
    /// Number of packets
    pub num_packets: u64,
    /// Number of bytes
    pub num_bytes: u64,
    /// First packet timestamp
    pub first_seen: u64,
    /// Last packet timestamp
    pub last_seen: u64,
}

impl TrafficStats {
    /// Increment statistics with new packet data
    pub fn inc_stats(&mut self, when: u64, num_packets: u64, num_bytes: u64) {
        self.num_packets += num_packets;
        self.num_bytes += num_bytes;
        if self.first_seen == 0 {
            self.first_seen = when;
        }
        self.last_seen = when;
    }

    /// Get the number of bytes
    pub fn get_num_bytes(&self) -> u64 {
        self.num_bytes
    }
}

/// TCP packet statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpPacketStats {
    /// Retransmitted packets
    pub retransmissions: u64,
    /// Out of order packets
    pub out_of_order: u64,
    /// Lost packets
    pub lost_packets: u64,
}

impl TcpPacketStats {
    /// Convert statistics to Lua table
    pub fn to_lua_table(&self, lua: &Lua, prefix: &str) -> mlua::Result<()> {
        let globals = lua.globals();
        globals.set(format!("{}.retransmissions", prefix), self.retransmissions)?;
        globals.set(format!("{}.out_of_order", prefix), self.out_of_order)?;
        globals.set(format!("{}.lost_packets", prefix), self.lost_packets)?;
        Ok(())
    }
}

/// Protocol statistics using nDPI
#[derive(Debug, Clone, Default)]
pub struct NDPIStats {
    stats: Vec<(u16, TrafficStats)>,
}

impl NDPIStats {
    /// Increment protocol statistics
    pub fn inc_stats(
        &mut self,
        when: u64,
        proto_id: u16,
        sent_packets: u64,
        sent_bytes: u64,
        rcvd_packets: u64,
        rcvd_bytes: u64,
    ) {
        if let Some(stats) = self.stats.iter_mut().find(|(id, _)| *id == proto_id) {
            stats.1.inc_stats(when, sent_packets + rcvd_packets, sent_bytes + rcvd_bytes);
        } else {
            let mut stats = TrafficStats::default();
            stats.inc_stats(when, sent_packets + rcvd_packets, sent_bytes + rcvd_bytes);
            self.stats.push((proto_id, stats));
        }
    }

    /// Convert statistics to Lua table
    pub fn to_lua(&self, iface: &NetworkInterface, lua: &Lua) -> mlua::Result<()> {
        let table = lua.create_table()?;
        for (proto_id, stats) in &self.stats {
            let proto_table = lua.create_table()?;
            proto_table.set("bytes", stats.num_bytes)?;
            proto_table.set("packets", stats.num_packets)?;
            table.set(*proto_id, proto_table)?;
        }
        lua.globals().set("ndpi_stats", table)?;
        Ok(())
    }
}

/// Represents an Autonomous System
#[derive(Debug)]
pub struct AutonomousSystem {
    /// AS number
    asn: u32,
    /// AS name
    asname: String,
    /// Round trip time (ms)
    round_trip_time: Arc<RwLock<u32>>,
    /// Number of alerted flows as client
    alerted_flows_as_client: Arc<RwLock<u32>>,
    /// Number of alerted flows as server
    alerted_flows_as_server: Arc<RwLock<u32>>,
    /// Sent traffic statistics
    sent: Arc<RwLock<TrafficStats>>,
    /// Received traffic statistics
    rcvd: Arc<RwLock<TrafficStats>>,
    /// TCP packet statistics for sent traffic
    tcp_packet_stats_sent: Arc<RwLock<TcpPacketStats>>,
    /// TCP packet statistics for received traffic
    tcp_packet_stats_rcvd: Arc<RwLock<TcpPacketStats>>,
    /// Protocol statistics
    ndpi_stats: Arc<RwLock<Option<NDPIStats>>>,
    /// Network interface reference
    iface: Arc<NetworkInterface>,
    /// First seen timestamp
    first_seen: Arc<RwLock<u64>>,
    /// Last seen timestamp
    last_seen: Arc<RwLock<u64>>,
    /// Number of hosts
    num_hosts: Arc<RwLock<u16>>,
}

impl AutonomousSystem {
    /// Create a new AutonomousSystem
    pub fn new(iface: Arc<NetworkInterface>, ip_address: &IpAddress) -> Self {
        let (asn, asname) = iface.get_geolocation().get_as(ip_address);
        
        Self {
            asn,
            asname,
            round_trip_time: Arc::new(RwLock::new(0)),
            alerted_flows_as_client: Arc::new(RwLock::new(0)),
            alerted_flows_as_server: Arc::new(RwLock::new(0)),
            sent: Arc::new(RwLock::new(TrafficStats::default())),
            rcvd: Arc::new(RwLock::new(TrafficStats::default())),
            tcp_packet_stats_sent: Arc::new(RwLock::new(TcpPacketStats::default())),
            tcp_packet_stats_rcvd: Arc::new(RwLock::new(TcpPacketStats::default())),
            ndpi_stats: Arc::new(RwLock::new(None)),
            iface,
            first_seen: Arc::new(RwLock::new(0)),
            last_seen: Arc::new(RwLock::new(0)),
            num_hosts: Arc::new(RwLock::new(0)),
        }
    }

    /// Get the AS number
    pub fn get_asn(&self) -> u32 {
        self.asn
    }

    /// Get the AS name
    pub fn get_asname(&self) -> &str {
        &self.asname
    }

    /// Check if this AS matches the given ASN
    pub fn equal(&self, asn: u32) -> bool {
        self.asn == asn
    }

    /// Get the number of hosts
    pub fn get_num_hosts(&self) -> u16 {
        *self.num_hosts.read()
    }

    /// Update round trip time using EWMA
    pub fn update_round_trip_time(&self, rtt_msecs: u32) {
        let mut rtt = self.round_trip_time.write();
        let ewma_alpha_percent = self.iface.get_prefs().get_ewma_alpha_percent();
        
        if *rtt > 0 {
            *rtt = (ewma_alpha_percent as u32 * rtt_msecs + 
                   (100 - ewma_alpha_percent) as u32 * *rtt) / 100;
        } else {
            *rtt = rtt_msecs;
        }
    }

    /// Increment statistics for sent traffic
    pub fn inc_sent_stats(&self, when: u64, num_packets: u64, num_bytes: u64) {
        let mut sent = self.sent.write();
        if *self.first_seen.read() == 0 {
            *self.first_seen.write() = when;
            *self.last_seen.write() = self.iface.get_time_last_pkt_rcvd();
        }
        sent.inc_stats(when, num_packets, num_bytes);
    }

    /// Increment statistics for received traffic
    pub fn inc_rcvd_stats(&self, when: u64, num_packets: u64, num_bytes: u64) {
        let mut rcvd = self.rcvd.write();
        rcvd.inc_stats(when, num_packets, num_bytes);
    }

    /// Increment statistics for a protocol
    pub fn inc_stats(
        &self,
        when: u64,
        proto_id: u16,
        sent_packets: u64,
        sent_bytes: u64,
        rcvd_packets: u64,
        rcvd_bytes: u64,
    ) {
        let mut ndpi_stats = self.ndpi_stats.write();
        if ndpi_stats.is_none() {
            *ndpi_stats = Some(NDPIStats::default());
        }
        if let Some(stats) = &mut *ndpi_stats {
            stats.inc_stats(when, proto_id, sent_packets, sent_bytes, rcvd_packets, rcvd_bytes);
        }
        self.inc_sent_stats(when, sent_packets, sent_bytes);
        self.inc_rcvd_stats(when, rcvd_packets, rcvd_bytes);
    }

    /// Increment the number of alerted flows
    pub fn inc_num_alerted_flows(&self, as_client: bool) {
        if as_client {
            *self.alerted_flows_as_client.write() += 1;
        } else {
            *self.alerted_flows_as_server.write() += 1;
        }
    }

    /// Get total number of alerted flows as client
    pub fn get_total_alerted_num_flows_as_client(&self) -> u32 {
        *self.alerted_flows_as_client.read()
    }

    /// Get total number of alerted flows as server
    pub fn get_total_alerted_num_flows_as_server(&self) -> u32 {
        *self.alerted_flows_as_server.read()
    }

    /// Convert to Lua table
    pub fn to_lua(
        &self,
        lua: &Lua,
        details_level: DetailsLevel,
        as_list_element: bool,
    ) -> mlua::Result<Table> {
        let table = lua.create_table()?;

        table.set("asn", self.asn)?;
        table.set("asname", &self.asname)?;
        table.set("bytes.sent", self.sent.read().get_num_bytes())?;
        table.set("bytes.rcvd", self.rcvd.read().get_num_bytes())?;

        if details_level >= DetailsLevel::High {
            table.set("seen.first", *self.first_seen.read())?;
            table.set("seen.last", *self.last_seen.read())?;
            table.set("num_hosts", self.get_num_hosts())?;
            table.set("round_trip_time", *self.round_trip_time.read())?;

            if details_level >= DetailsLevel::Higher {
                if let Some(stats) = &*self.ndpi_stats.read() {
                    stats.to_lua(&self.iface, lua)?;
                }
                self.tcp_packet_stats_sent.read().to_lua_table(lua, "tcpPacketStats.sent")?;
                self.tcp_packet_stats_rcvd.read().to_lua_table(lua, "tcpPacketStats.rcvd")?;
            }
        }

        let alerted_flows = lua.create_table()?;
        alerted_flows.set("as_client", self.get_total_alerted_num_flows_as_client())?;
        alerted_flows.set("as_server", self.get_total_alerted_num_flows_as_server())?;
        alerted_flows.set(
            "total",
            self.get_total_alerted_num_flows_as_client() + self.get_total_alerted_num_flows_as_server(),
        )?;
        table.set("alerted_flows", alerted_flows)?;

        if as_list_element {
            let globals = lua.globals();
            globals.set(self.asn.to_string(), table.clone())?;
        }

        Ok(table)
    }

    /// Update statistics
    pub fn update_stats(&self, tv: SystemTime) {
        let timestamp = tv.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        *self.last_seen.write() = timestamp;
    }
}

/// Placeholder for NetworkInterface implementation
pub struct NetworkInterface {
    // Add fields as needed
}

impl NetworkInterface {
    pub fn get_geolocation(&self) -> &Geolocation {
        unimplemented!()
    }

    pub fn get_time_last_pkt_rcvd(&self) -> u64 {
        unimplemented!()
    }

    pub fn get_prefs(&self) -> &Preferences {
        unimplemented!()
    }
}

/// Placeholder for Geolocation implementation
pub struct Geolocation;

impl Geolocation {
    pub fn get_as(&self, _ip: &IpAddress) -> (u32, String) {
        unimplemented!()
    }
}

/// Placeholder for Preferences implementation
pub struct Preferences;

impl Preferences {
    pub fn get_ewma_alpha_percent(&self) -> u8 {
        unimplemented!()
    }
}

/// Placeholder for IpAddress implementation
pub struct IpAddress;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_stats() {
        let mut stats = TrafficStats::default();
        assert_eq!(stats.num_packets, 0);
        assert_eq!(stats.num_bytes, 0);
        
        stats.inc_stats(100, 10, 1000);
        assert_eq!(stats.num_packets, 10);
        assert_eq!(stats.num_bytes, 1000);
        assert_eq!(stats.first_seen, 100);
        assert_eq!(stats.last_seen, 100);
    }

    #[test]
    fn test_tcp_packet_stats() {
        let stats = TcpPacketStats {
            retransmissions: 10,
            out_of_order: 5,
            lost_packets: 2,
        };
        
        let lua = Lua::new();
        stats.to_lua_table(&lua, "tcp").unwrap();
        
        assert_eq!(
            lua.globals().get::<_, u64>("tcp.retransmissions").unwrap(),
            10
        );
    }
}
