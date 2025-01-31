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

use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::{Arc, Mutex, atomic::{AtomicU32, Ordering}};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use dns_lookup::{lookup_addr, lookup_host};

const MAX_NUM_IDLE_LOOPS: u32 = 1;
const NI_MAXHOST: usize = 1025;

#[derive(Debug)]
pub struct AddressResolution {
    num_resolvers: usize,
    num_resolved_addresses: Arc<AtomicU32>,
    num_resolved_fails: Arc<AtomicU32>,
    resolve_threads: Vec<Option<JoinHandle<()>>>,
    mutex: Arc<Mutex<()>>,
    redis: Arc<Redis>,  // Assuming Redis is a type from your codebase
    ntop: Arc<Ntop>,   // Assuming Ntop is a type from your codebase
}

impl AddressResolution {
    pub fn new(num_resolvers: usize, redis: Arc<Redis>, ntop: Arc<Ntop>) -> Result<Self, String> {
        Ok(Self {
            num_resolvers,
            num_resolved_addresses: Arc::new(AtomicU32::new(0)),
            num_resolved_fails: Arc::new(AtomicU32::new(0)),
            resolve_threads: vec![None; num_resolvers],
            mutex: Arc::new(Mutex::new(())),
            redis,
            ntop,
        })
    }

    pub fn start_resolve_address_loop(&mut self) {
        if !self.ntop.get_prefs().is_dns_resolution_enabled() {
            return;
        }

        for i in 0..self.num_resolvers {
            let redis = Arc::clone(&self.redis);
            let ntop = Arc::clone(&self.ntop);
            let num_resolved_addresses = Arc::clone(&self.num_resolved_addresses);
            let num_resolved_fails = Arc::clone(&self.num_resolved_fails);
            let mutex = Arc::clone(&self.mutex);

            let handle = thread::spawn(move || {
                let mut no_resolution_loops = 0;

                while !ntop.get_globals().is_shutdown() {
                    match redis.pop_host_to_resolve() {
                        Ok(Some(numeric_ip)) if !numeric_ip.is_empty() => {
                            Self::resolve_host_name_internal(
                                &numeric_ip,
                                None,
                                &redis,
                                &ntop,
                                &num_resolved_addresses,
                                &num_resolved_fails,
                                &mutex,
                            );
                            no_resolution_loops = 0;
                        }
                        _ => {
                            if no_resolution_loops < MAX_NUM_IDLE_LOOPS {
                                no_resolution_loops += 1;
                            }
                            thread::sleep(Duration::from_secs(no_resolution_loops as u64));
                        }
                    }

                    if ntop.get_globals().is_shutdown_requested() {
                        break;
                    }
                }
            });

            self.resolve_threads[i] = Some(handle);
        }
    }

    pub fn resolve_host_name(&self, numeric_ip: &str, symbolic: Option<&mut [u8]>) -> Result<(), String> {
        Self::resolve_host_name_internal(
            numeric_ip,
            symbolic,
            &self.redis,
            &self.ntop,
            &self.num_resolved_addresses,
            &self.num_resolved_fails,
            &self.mutex,
        )
    }

    fn resolve_host_name_internal(
        numeric_ip: &str,
        mut symbolic: Option<&mut [u8]>,
        redis: &Redis,
        ntop: &Ntop,
        num_resolved_addresses: &AtomicU32,
        num_resolved_fails: &AtomicU32,
        mutex: &Mutex<()>,
    ) -> Result<(), String> {
        if numeric_ip.is_empty() {
            return Ok(());
        }

        // Clear symbolic buffer if provided
        if let Some(ref mut sym) = symbolic {
            sym[0] = 0;
        }

        // Try to get from Redis cache first
        if let Ok(Some(cached)) = redis.get_address(numeric_ip) {
            if let Some(sym) = symbolic {
                let len = sym.len().min(cached.len());
                sym[..len].copy_from_slice(&cached.as_bytes()[..len]);
                sym[len] = 0;
            }
            return Ok(());
        }

        if !ntop.get_prefs().is_dns_resolution_enabled() {
            return Ok(());
        }

        // Check if this is a symbolic IP
        if !numeric_ip.chars().last().map_or(false, |c| c.is_ascii_hexdigit() || c == ':') {
            let _lock = mutex.lock().map_err(|e| e.to_string())?;
            
            // This is a symbolic IP -> numeric IP
            match lookup_host(numeric_ip) {
                Ok(addrs) => {
                    if let Some(addr) = addrs.first() {
                        let hostname = addr.to_string();
                        if let Some(sym) = symbolic {
                            let len = sym.len().min(hostname.len());
                            sym[..len].copy_from_slice(&hostname.as_bytes()[..len]);
                            sym[len] = 0;
                        }
                        redis.set_resolved_address(numeric_ip, &hostname)?;
                        num_resolved_addresses.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(e) => {
                    ntop.get_trace().trace_event(TraceLevel::Info, &format!(
                        "Error resolving symbolic address {}: {}", numeric_ip, e
                    ));
                    num_resolved_fails.fetch_add(1, Ordering::SeqCst);
                    redis.set_resolved_address(numeric_ip, numeric_ip)?;
                }
            }
            return Ok(());
        }

        // Handle IPv4/IPv6 address resolution
        let ip: IpAddr = numeric_ip.parse().map_err(|e| e.to_string())?;
        match lookup_addr(&ip) {
            Ok(hostname) => {
                if let Some(sym) = symbolic {
                    let len = sym.len().min(hostname.len());
                    sym[..len].copy_from_slice(&hostname.as_bytes()[..len]);
                    sym[len] = 0;
                }
                redis.set_resolved_address(numeric_ip, &hostname)?;
                num_resolved_addresses.fetch_add(1, Ordering::SeqCst);
                ntop.get_trace().trace_event(TraceLevel::Debug, &format!(
                    "Resolved {} to {}", numeric_ip, hostname
                ));
            }
            Err(e) => {
                num_resolved_fails.fetch_add(1, Ordering::SeqCst);
                ntop.get_trace().trace_event(TraceLevel::Info, &format!(
                    "Error resolving address {}: {}", numeric_ip, e
                ));
                redis.set_resolved_address(numeric_ip, numeric_ip)?;
            }
        }

        Ok(())
    }

    pub fn resolve_host(&self, host: &str, rsp: &mut [u8], v4: bool) -> Result<bool, String> {
        if host.is_empty() {
            return Ok(false);
        }

        let addrs = lookup_host(host).map_err(|e| e.to_string())?;
        
        for addr in addrs {
            if (v4 && addr.is_ipv4()) || (!v4 && addr.is_ipv6()) {
                let addr_str = addr.to_string();
                let len = rsp.len().min(addr_str.len());
                rsp[..len].copy_from_slice(&addr_str.as_bytes()[..len]);
                rsp[len] = 0;
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl Drop for AddressResolution {
    fn drop(&mut self) {
        // Wait for resolver threads to finish
        for handle in self.resolve_threads.iter_mut().filter_map(Option::take) {
            let _ = handle.join();
        }

        // Log final stats
        if let Ok(trace) = self.ntop.get_trace() {
            trace.trace_event(TraceLevel::Normal, &format!(
                "Address resolution stats [{}resolved][{}failures]",
                self.num_resolved_addresses.load(Ordering::SeqCst),
                self.num_resolved_fails.load(Ordering::SeqCst)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_resolve_host() {
        // Mock dependencies
        let redis = Arc::new(Redis::new()); // You'll need to implement mock Redis
        let ntop = Arc::new(Ntop::new());   // You'll need to implement mock Ntop
        
        let resolver = AddressResolution::new(2, redis, ntop).unwrap();
        
        let mut response = vec![0u8; NI_MAXHOST];
        
        // Test IPv4 resolution
        assert!(resolver.resolve_host("localhost", &mut response, true).unwrap());
        assert_eq!(std::str::from_utf8(&response).unwrap().trim_matches(char::from(0)), "127.0.0.1");
        
        // Test IPv6 resolution
        let mut response = vec![0u8; NI_MAXHOST];
        assert!(resolver.resolve_host("localhost", &mut response, false).unwrap());
        assert!(std::str::from_utf8(&response).unwrap().trim_matches(char::from(0)).contains("::1"));
    }

    #[test]
    fn test_resolve_host_name() {
        // Mock dependencies
        let redis = Arc::new(Redis::new()); // You'll need to implement mock Redis
        let ntop = Arc::new(Ntop::new());   // You'll need to implement mock Ntop
        
        let resolver = AddressResolution::new(2, redis, ntop).unwrap();
        
        let mut response = vec![0u8; NI_MAXHOST];
        
        // Test IP resolution
        resolver.resolve_host_name("127.0.0.1", Some(&mut response)).unwrap();
        assert!(std::str::from_utf8(&response).unwrap().trim_matches(char::from(0)).contains("localhost"));
        
        // Test invalid IP
        assert!(resolver.resolve_host_name("invalid-ip", Some(&mut response)).is_ok());
    }
}
