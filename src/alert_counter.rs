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

use std::time::{SystemTime, UNIX_EPOCH};
use crate::alertable_entity::AlertableEntity;

/// Base class for handling generated alerts.
///
/// This struct provides functionality for counting and tracking alert hits over time,
/// with support for windowed counting and hit rate tracking.
#[derive(Debug)]
pub struct AlertCounter {
    /// Timestamp of the last hit
    time_last_hit: u64,
    /// Number of hits in the current window
    current_hits: u16,
    /// Maximum number of hits seen in any window since last reset
    max_hits_since_reset: u16,
    /// Flag indicating if a hits reset has been requested
    hits_reset_req: bool,
}

impl Default for AlertCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertCounter {
    /// Creates a new AlertCounter with zeroed counters
    pub fn new() -> Self {
        let mut counter = Self {
            time_last_hit: 0,
            current_hits: 0,
            max_hits_since_reset: 0,
            hits_reset_req: false,
        };
        counter.reset_window(None);
        counter
    }

    /// Resets the current window counters
    ///
    /// # Arguments
    /// * `when` - Optional timestamp for the reset. If None, uses current time.
    fn reset_window(&mut self, when: Option<u64>) {
        self.current_hits = 0;
        self.time_last_hit = when.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
    }

    /// Increments the hit counter
    ///
    /// # Arguments
    /// * `when` - Timestamp of the hit
    /// * `alertable` - Reference to the AlertableEntity that generated the hit
    pub fn inc(&mut self, when: u64, _alertable: &AlertableEntity) {
        if self.hits_reset_req {
            self.max_hits_since_reset = 0;
            self.hits_reset_req = false;
            self.reset_window(Some(when));
        }

        // If more than 1 second has passed since last hit
        if when.saturating_sub(self.time_last_hit) > 1 {
            if self.current_hits > self.max_hits_since_reset {
                self.max_hits_since_reset = self.current_hits;
            }
            self.reset_window(Some(when));
        } else {
            self.current_hits = self.current_hits.saturating_add(1);
        }

        #[cfg(feature = "debug_alerts")]
        log::debug!(
            "stats [host: {}][when: {}][time_last_hit: {}][max_hits_since_reset: {}][current_hits: {}]",
            alertable.get_entity_value(),
            when,
            self.time_last_hit,
            self.max_hits_since_reset,
            self.current_hits
        );
    }

    /// Returns the current number of hits
    ///
    /// Returns 0 if a reset has been requested but not yet processed.
    /// Otherwise returns the maximum of current_hits and max_hits_since_reset.
    pub fn hits(&self) -> u16 {
        if self.hits_reset_req {
            0
        } else {
            self.max_hits_since_reset.max(self.current_hits)
        }
    }

    /// Requests a reset of the hit counters
    ///
    /// The reset will be performed on the next call to inc()
    pub fn reset_hits(&mut self) {
        self.hits_reset_req = true;
    }
}

/// Represents counters for both attacker and victim in an attack scenario
#[derive(Debug)]
pub struct AttackVictimCounter {
    /// Counter for the attacker
    pub attacker_counter: AlertCounter,
    /// Counter for the victim
    pub victim_counter: AlertCounter,
}

impl Default for AttackVictimCounter {
    fn default() -> Self {
        Self {
            attacker_counter: AlertCounter::new(),
            victim_counter: AlertCounter::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alertable_entity::{AlertableEntity, AlertEntity};
    use std::sync::Arc;
    use crate::alertable_entity::NetworkInterface;

    #[test]
    fn test_alert_counter_new() {
        let counter = AlertCounter::new();
        assert_eq!(counter.hits(), 0);
        assert!(!counter.hits_reset_req);
    }

    #[test]
    fn test_alert_counter_inc() {
        let mut counter = AlertCounter::new();
        let iface = Arc::new(NetworkInterface {});
        let entity = AlertableEntity::new(iface, AlertEntity::Host);

        // First hit
        counter.inc(100, &entity);
        assert_eq!(counter.current_hits, 1);

        // Second hit within same second
        counter.inc(100, &entity);
        assert_eq!(counter.current_hits, 2);

        // Hit after window
        counter.inc(102, &entity);
        assert_eq!(counter.current_hits, 1);
        assert_eq!(counter.max_hits_since_reset, 2);
    }

    #[test]
    fn test_alert_counter_reset() {
        let mut counter = AlertCounter::new();
        let iface = Arc::new(NetworkInterface {});
        let entity = AlertableEntity::new(iface, AlertEntity::Host);

        // Add some hits
        counter.inc(100, &entity);
        counter.inc(100, &entity);
        assert_eq!(counter.hits(), 2);

        // Request reset
        counter.reset_hits();
        assert_eq!(counter.hits(), 0);

        // Next inc should reset counters
        counter.inc(101, &entity);
        assert_eq!(counter.max_hits_since_reset, 0);
        assert_eq!(counter.current_hits, 1);
    }

    #[test]
    fn test_attack_victim_counter() {
        let counter = AttackVictimCounter::default();
        assert_eq!(counter.attacker_counter.hits(), 0);
        assert_eq!(counter.victim_counter.hits(), 0);
    }
}
