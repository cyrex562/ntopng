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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::ffi::CStr;
use std::os::raw::c_char;
use patricia_tree::{PatriciaMap, PatriciaSet};
use mlua::{Lua, Table};

type MacAddress = [u8; 6];

#[derive(Debug)]
pub struct AddressTree {
    num_addresses: u32,
    num_addresses_ipv4: u32,
    num_addresses_ipv6: u32,
    ptree_v4: RwLock<PatriciaMap<Vec<u8>, Box<dyn std::any::Any + Send + Sync>>>,
    ptree_v6: Option<RwLock<PatriciaMap<Vec<u8>, Box<dyn std::any::Any + Send + Sync>>>>,
    macs: RwLock<HashMap<u64, i64>>,
}

impl AddressTree {
    pub fn new(handle_ipv6: bool) -> Self {
        Self {
            num_addresses: 0,
            num_addresses_ipv4: 0,
            num_addresses_ipv6: 0,
            ptree_v4: RwLock::new(PatriciaMap::new()),
            ptree_v6: if handle_ipv6 {
                Some(RwLock::new(PatriciaMap::new()))
            } else {
                None
            },
            macs: RwLock::new(HashMap::new()),
        }
    }

    pub fn clone_from(&mut self, other: &AddressTree) -> Result<(), String> {
        let _guard = self.ptree_v4.write().map_err(|e| e.to_string())?;
        self.ptree_v4 = RwLock::new(other.ptree_v4.read().map_err(|e| e.to_string())?.clone());
        
        if let Some(ref other_v6) = other.ptree_v6 {
            self.ptree_v6 = Some(RwLock::new(
                other_v6.read().map_err(|e| e.to_string())?.clone()
            ));
        }

        let mut macs = self.macs.write().map_err(|e| e.to_string())?;
        *macs = other.macs.read().map_err(|e| e.to_string())?.clone();

        self.num_addresses = other.num_addresses;
        self.num_addresses_ipv4 = other.num_addresses_ipv4;
        self.num_addresses_ipv6 = other.num_addresses_ipv6;

        Ok(())
    }

    pub fn add_address(&mut self, ip: IpAddr, network_bits: Option<u32>, user_data: Option<Box<dyn std::any::Any + Send + Sync>>) -> Result<(), String> {
        let bits = network_bits.unwrap_or(match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        });

        let bytes = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        let tree = match ip {
            IpAddr::V4(_) => &self.ptree_v4,
            IpAddr::V6(_) => self.ptree_v6.as_ref().ok_or("IPv6 not supported")?,
        };

        let mut tree = tree.write().map_err(|e| e.to_string())?;

        if !tree.contains_key(&bytes) {
            if let Some(data) = user_data {
                tree.insert(bytes, data);
            } else {
                tree.insert(bytes, Box::new(self.num_addresses as i64));
            }

            self.num_addresses += 1;
            match ip {
                IpAddr::V4(_) => self.num_addresses_ipv4 += 1,
                IpAddr::V6(_) => self.num_addresses_ipv6 += 1,
            }
        }

        Ok(())
    }

    pub fn add_mac(&mut self, mac: MacAddress, user_data: i64) -> Result<(), String> {
        let mac_int = u64::from_be_bytes([0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
        let mut macs = self.macs.write().map_err(|e| e.to_string())?;
        macs.insert(mac_int, user_data);
        Ok(())
    }

    pub fn find_address(&self, ip: IpAddr) -> Result<Option<i64>, String> {
        let bytes = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        let tree = match ip {
            IpAddr::V4(_) => &self.ptree_v4,
            IpAddr::V6(_) => self.ptree_v6.as_ref().ok_or("IPv6 not supported")?,
        };

        let tree = tree.read().map_err(|e| e.to_string())?;
        
        if let Some(data) = tree.get_longest_match(&bytes) {
            if let Ok(value) = data.downcast_ref::<i64>() {
                Ok(Some(*value))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn find_mac(&self, mac: &MacAddress) -> Result<Option<i64>, String> {
        let mac_int = u64::from_be_bytes([0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
        let macs = self.macs.read().map_err(|e| e.to_string())?;
        Ok(macs.get(&mac_int).copied())
    }

    pub fn to_lua(&self, lua: &Lua) -> mlua::Result<Table> {
        let table = lua.create_table()?;
        
        // IPv4 addresses
        {
            let tree = self.ptree_v4.read().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            let ipv4_table = lua.create_table()?;
            for (key, value) in tree.iter() {
                if let Ok(value) = value.downcast_ref::<i64>() {
                    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&key[..4]).unwrap());
                    ipv4_table.set(ip.to_string(), *value)?;
                }
            }
            table.set("ipv4", ipv4_table)?;
        }

        // IPv6 addresses
        if let Some(ref tree_v6) = self.ptree_v6 {
            let tree = tree_v6.read().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            let ipv6_table = lua.create_table()?;
            for (key, value) in tree.iter() {
                if let Ok(value) = value.downcast_ref::<i64>() {
                    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&key[..16]).unwrap());
                    ipv6_table.set(ip.to_string(), *value)?;
                }
            }
            table.set("ipv6", ipv6_table)?;
        }

        // MAC addresses
        let macs = self.macs.read().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        let mac_table = lua.create_table()?;
        for (mac, value) in macs.iter() {
            let mac_bytes = mac.to_be_bytes();
            let mac_str = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5], mac_bytes[6], mac_bytes[7]
            );
            mac_table.set(mac_str, *value)?;
        }
        table.set("mac", mac_table)?;

        Ok(table)
    }

    pub fn get_num_addresses(&self) -> u32 {
        self.num_addresses
    }

    pub fn get_num_addresses_ipv4(&self) -> u32 {
        self.num_addresses_ipv4
    }

    pub fn get_num_addresses_ipv6(&self) -> u32 {
        self.num_addresses_ipv6
    }

    pub fn is_empty(&self) -> bool {
        self.num_addresses == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_address_tree_basic() {
        let mut tree = AddressTree::new(true);
        
        // Test IPv4
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        tree.add_address(ip, None, None).unwrap();
        assert_eq!(tree.get_num_addresses(), 1);
        assert_eq!(tree.get_num_addresses_ipv4(), 1);
        
        // Test IPv6
        let ip = IpAddr::from_str("2001:db8::1").unwrap();
        tree.add_address(ip, None, None).unwrap();
        assert_eq!(tree.get_num_addresses(), 2);
        assert_eq!(tree.get_num_addresses_ipv6(), 1);
        
        // Test MAC
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        tree.add_mac(mac, 42).unwrap();
        assert_eq!(tree.find_mac(&mac).unwrap(), Some(42));
    }

    #[test]
    fn test_address_tree_find() {
        let mut tree = AddressTree::new(true);
        
        // Add and find IPv4
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        tree.add_address(ip, None, Some(Box::new(42i64))).unwrap();
        assert_eq!(tree.find_address(ip).unwrap(), Some(42));
        
        // Add and find IPv6
        let ip = IpAddr::from_str("2001:db8::1").unwrap();
        tree.add_address(ip, None, Some(Box::new(43i64))).unwrap();
        assert_eq!(tree.find_address(ip).unwrap(), Some(43));
        
        // Test non-existent address
        let ip = IpAddr::from_str("192.168.1.2").unwrap();
        assert_eq!(tree.find_address(ip).unwrap(), None);
    }

    #[test]
    fn test_lua_conversion() -> mlua::Result<()> {
        let mut tree = AddressTree::new(true);
        let lua = Lua::new();
        
        // Add some test data
        let ip4 = IpAddr::from_str("192.168.1.1").unwrap();
        let ip6 = IpAddr::from_str("2001:db8::1").unwrap();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        
        tree.add_address(ip4, None, Some(Box::new(42i64))).unwrap();
        tree.add_address(ip6, None, Some(Box::new(43i64))).unwrap();
        tree.add_mac(mac, 44).unwrap();
        
        let table = tree.to_lua(&lua)?;
        
        let ipv4_table: Table = table.get("ipv4")?;
        assert_eq!(ipv4_table.get::<_, i64>("192.168.1.1")?, 42);
        
        let ipv6_table: Table = table.get("ipv6")?;
        assert_eq!(ipv6_table.get::<_, i64>("2001:db8::1")?, 43);
        
        let mac_table: Table = table.get("mac")?;
        assert_eq!(mac_table.get::<_, i64>("00:11:22:33:44:55")?, 44);
        
        Ok(())
    }
}
