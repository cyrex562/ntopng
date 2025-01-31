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
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use log::{debug, trace};
use crate::autonomous_system::AutonomousSystem;
use crate::autonomous_system::IpAddress;

/// Configuration for the hash table
#[derive(Debug, Clone)]
pub struct HashConfig {
    /// Number of hash buckets
    pub num_buckets: usize,
    /// Maximum size of each bucket
    pub max_bucket_size: usize,
    /// Cleanup interval in seconds
    pub cleanup_interval: u64,
    /// Maximum age of entries in seconds
    pub max_age: u64,
}

impl Default for HashConfig {
    fn default() -> Self {
        Self {
            num_buckets: 32768,
            max_bucket_size: 2048,
            cleanup_interval: 300,
            max_age: 3600,
        }
    }
}

/// A thread-safe hash table for Autonomous Systems
#[derive(Debug)]
pub struct AutonomousSystemHash {
    /// Network interface reference
    iface: Arc<NetworkInterface>,
    /// Hash table configuration
    config: HashConfig,
    /// The actual hash table, divided into buckets for better concurrency
    buckets: Vec<RwLock<HashMap<u32, Arc<AutonomousSystem>>>>,
    /// Last cleanup time
    last_cleanup: RwLock<SystemTime>,
    /// Whether cleanup is enabled
    cleanup_enabled: RwLock<bool>,
}

impl AutonomousSystemHash {
    /// Create a new AutonomousSystemHash
    pub fn new(
        iface: Arc<NetworkInterface>,
        config: HashConfig,
    ) -> Self {
        let buckets = (0..config.num_buckets)
            .map(|_| RwLock::new(HashMap::with_capacity(config.max_bucket_size)))
            .collect();

        Self {
            iface,
            config,
            buckets,
            last_cleanup: RwLock::new(SystemTime::now()),
            cleanup_enabled: RwLock::new(true),
        }
    }

    /// Get or create an AutonomousSystem for the given IP address
    pub fn get(&self, ip: &IpAddress, is_inline_call: bool) -> Option<Arc<AutonomousSystem>> {
        // Get ASN from geolocation service
        let asn = self.iface.get_geolocation().get_as(ip).0;
        let bucket_idx = (asn as usize) % self.config.num_buckets;

        // Try to get from cache first
        let bucket = &self.buckets[bucket_idx];
        let read_guard = bucket.read();
        
        if let Some(as_ref) = read_guard.get(&asn) {
            if !as_ref.is_idle() {
                return Some(Arc::clone(as_ref));
            }
        }
        drop(read_guard);

        // Not found or idle, create new one
        let mut write_guard = bucket.write();
        if write_guard.len() >= self.config.max_bucket_size {
            debug!("Bucket {} is full, cannot add new AS", bucket_idx);
            return None;
        }

        let as_entry = Arc::new(AutonomousSystem::new(Arc::clone(&self.iface), ip));
        write_guard.insert(asn, Arc::clone(&as_entry));
        
        if !is_inline_call {
            self.maybe_cleanup();
        }

        Some(as_entry)
    }

    /// Enable automatic cleanup
    pub fn enable_cleanup(&self) {
        *self.cleanup_enabled.write() = true;
    }

    /// Disable automatic cleanup
    pub fn disable_cleanup(&self) {
        *self.cleanup_enabled.write() = false;
    }

    /// Check if cleanup is needed and perform it if necessary
    fn maybe_cleanup(&self) {
        if !*self.cleanup_enabled.read() {
            return;
        }

        let now = SystemTime::now();
        let last = *self.last_cleanup.read();
        
        if now.duration_since(last).unwrap_or_default() > Duration::from_secs(self.config.cleanup_interval) {
            self.cleanup();
            *self.last_cleanup.write() = now;
        }
    }

    /// Clean up old entries
    fn cleanup(&self) {
        let now = SystemTime::now();
        let max_age = Duration::from_secs(self.config.max_age);

        for bucket in &self.buckets {
            let mut guard = bucket.write();
            guard.retain(|_, as_ref| {
                let age = now.duration_since(as_ref.get_last_seen())
                    .unwrap_or_default();
                age <= max_age && !as_ref.is_idle()
            });
        }
    }

    /// Walk through all entries and apply a function
    pub fn walk<F>(&self, mut f: F)
    where
        F: FnMut(&Arc<AutonomousSystem>) -> bool,
    {
        for bucket in &self.buckets {
            let guard = bucket.read();
            for as_ref in guard.values() {
                if f(as_ref) {
                    return;
                }
            }
        }
    }

    /// Print debug information about the hash table
    #[cfg(feature = "debug")]
    pub fn print_hash(&self) {
        self.disable_cleanup();

        self.walk(|as_ref| {
            trace!(
                "Autonomous System [asn: {}] [asname: {}] [num_hosts: {}]",
                as_ref.get_asn(),
                as_ref.get_asname(),
                as_ref.get_num_hosts()
            );
            false
        });

        self.enable_cleanup();
    }

    /// Get statistics about the hash table
    pub fn get_stats(&self) -> HashStats {
        let mut stats = HashStats::default();
        
        for bucket in &self.buckets {
            let guard = bucket.read();
            stats.total_entries += guard.len();
            stats.max_bucket_size = stats.max_bucket_size.max(guard.len());
        }
        
        stats.num_buckets = self.buckets.len();
        stats.avg_bucket_size = stats.total_entries as f64 / self.buckets.len() as f64;
        
        stats
    }
}

/// Statistics about the hash table
#[derive(Debug, Default)]
pub struct HashStats {
    /// Total number of entries
    pub total_entries: usize,
    /// Number of buckets
    pub num_buckets: usize,
    /// Maximum bucket size
    pub max_bucket_size: usize,
    /// Average bucket size
    pub avg_bucket_size: f64,
}

/// Placeholder for NetworkInterface
pub struct NetworkInterface {
    // Add fields as needed
}

impl NetworkInterface {
    pub fn get_geolocation(&self) -> &Geolocation {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_hash_basic_operations() {
        let iface = Arc::new(NetworkInterface {});
        let config = HashConfig::default();
        let hash = AutonomousSystemHash::new(Arc::clone(&iface), config);

        // Test get operation
        let ip = IpAddress {}; // Mock IP
        let as_entry = hash.get(&ip, false).unwrap();
        assert_eq!(as_entry.get_asn(), 0); // Mock ASN

        // Test stats
        let stats = hash.get_stats();
        assert_eq!(stats.total_entries, 1);
        assert!(stats.avg_bucket_size > 0.0);
    }

    #[test]
    fn test_hash_cleanup() {
        let iface = Arc::new(NetworkInterface {});
        let mut config = HashConfig::default();
        config.cleanup_interval = 0; // Immediate cleanup
        config.max_age = 0; // All entries are old
        
        let hash = AutonomousSystemHash::new(Arc::clone(&iface), config);
        
        // Add an entry
        let ip = IpAddress {}; // Mock IP
        let _ = hash.get(&ip, false);
        
        // Force cleanup
        hash.cleanup();
        
        // Check that entry was removed
        let stats = hash.get_stats();
        assert_eq!(stats.total_entries, 0);
    }
}
