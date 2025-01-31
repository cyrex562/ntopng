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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralConfig {
    /// Learning phase window size
    pub learning_window: u32,
    /// Confidence interval (0.0 to 1.0)
    pub confidence_interval: f64,
    /// Minimum number of observations required
    pub min_observations: u32,
    /// Maximum allowed deviation from mean
    pub max_deviation: f64,
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            learning_window: 100,
            confidence_interval: 0.95,
            min_observations: 30,
            max_deviation: 3.0,
        }
    }
}

/// Statistics for behavioral analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehavioralStats {
    /// Number of observations
    pub observations: u64,
    /// Number of anomalies detected
    pub anomalies: u64,
    /// Current mean value
    pub mean: f64,
    /// Current standard deviation
    pub std_dev: f64,
    /// Last observation time
    pub last_update: u64,
}

/// Represents a behavioral counter that can detect anomalies in a series of observations
#[derive(Debug)]
pub struct BehavioralCounter {
    /// Whether the current value is anomalous
    is_anomaly: AtomicBool,
    /// Total number of anomalies detected
    tot_num_anomalies: AtomicU64,
    /// Last lower bound
    last_lower: AtomicU64,
    /// Last upper bound
    last_upper: AtomicU64,
    /// Last observed value
    last_value: AtomicU64,
    /// Configuration for the counter
    config: BehavioralConfig,
    /// Current statistics
    stats: parking_lot::RwLock<BehavioralStats>,
}

impl BehavioralCounter {
    /// Creates a new BehavioralCounter with the given configuration
    pub fn new(config: BehavioralConfig) -> Self {
        Self {
            is_anomaly: AtomicBool::new(false),
            tot_num_anomalies: AtomicU64::new(0),
            last_lower: AtomicU64::new(0),
            last_upper: AtomicU64::new(0),
            last_value: AtomicU64::new(0),
            config,
            stats: parking_lot::RwLock::new(BehavioralStats::default()),
        }
    }

    /// Creates a new BehavioralCounter with default configuration
    pub fn default() -> Self {
        Self::new(BehavioralConfig::default())
    }

    /// Adds a new observation and checks for anomalies
    /// 
    /// Returns true if an anomaly was detected
    pub fn add_observation(&self, value: u64) -> bool {
        let mut stats = self.stats.write();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Update last value
        self.last_value.store(value, Ordering::Relaxed);
        stats.last_update = now;
        stats.observations += 1;

        // Update statistics
        let old_mean = stats.mean;
        let n = stats.observations as f64;
        stats.mean += (value as f64 - stats.mean) / n;

        if n > 1.0 {
            stats.std_dev = (((n - 2.0) * stats.std_dev.powi(2) + 
                           (value as f64 - old_mean) * (value as f64 - stats.mean)) / (n - 1.0))
                           .sqrt();
        }

        // Check for anomalies only after minimum observations
        if stats.observations < self.config.min_observations as u64 {
            self.is_anomaly.store(false, Ordering::Relaxed);
            return false;
        }

        // Calculate bounds using confidence interval
        let z_score = self.config.max_deviation;
        let lower_bound = (stats.mean - z_score * stats.std_dev) as u64;
        let upper_bound = (stats.mean + z_score * stats.std_dev) as u64;

        self.last_lower.store(lower_bound, Ordering::Relaxed);
        self.last_upper.store(upper_bound, Ordering::Relaxed);

        // Check for anomaly
        let is_anomaly = value < lower_bound || value > upper_bound;
        self.is_anomaly.store(is_anomaly, Ordering::Relaxed);

        if is_anomaly {
            self.tot_num_anomalies.fetch_add(1, Ordering::Relaxed);
            stats.anomalies += 1;
        }

        is_anomaly
    }

    /// Returns whether an anomaly was found in the last observation
    pub fn anomaly_found(&self) -> bool {
        self.is_anomaly.load(Ordering::Relaxed)
    }

    /// Returns the last observed value
    pub fn get_last_value(&self) -> u64 {
        self.last_value.load(Ordering::Relaxed)
    }

    /// Returns the total number of anomalies detected
    pub fn get_tot_anomalies(&self) -> u64 {
        self.tot_num_anomalies.load(Ordering::Relaxed)
    }

    /// Returns the last lower bound
    pub fn get_last_lower_bound(&self) -> u64 {
        self.last_lower.load(Ordering::Relaxed)
    }

    /// Returns the last upper bound
    pub fn get_last_upper_bound(&self) -> u64 {
        self.last_upper.load(Ordering::Relaxed)
    }

    /// Returns the current statistics
    pub fn get_stats(&self) -> BehavioralStats {
        self.stats.read().clone()
    }

    /// Returns the current configuration
    pub fn get_config(&self) -> BehavioralConfig {
        self.config.clone()
    }

    /// Updates the configuration
    pub fn update_config(&mut self, config: BehavioralConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavioral_counter_basic() {
        let counter = BehavioralCounter::default();
        
        // Test initial state
        assert_eq!(counter.get_last_value(), 0);
        assert_eq!(counter.get_tot_anomalies(), 0);
        assert!(!counter.anomaly_found());

        // Add some normal values
        for i in 1..=30 {
            counter.add_observation(i);
        }

        // Add an anomaly
        let is_anomaly = counter.add_observation(1000);
        assert!(is_anomaly);
        assert!(counter.anomaly_found());
        assert_eq!(counter.get_tot_anomalies(), 1);
    }

    #[test]
    fn test_behavioral_counter_statistics() {
        let counter = BehavioralCounter::default();
        
        // Add consistent values
        for _ in 0..100 {
            counter.add_observation(50);
        }

        let stats = counter.get_stats();
        assert_eq!(stats.observations, 100);
        assert!(stats.mean > 49.9 && stats.mean < 50.1);
        assert!(stats.std_dev < 0.1);
    }

    #[test]
    fn test_behavioral_counter_bounds() {
        let mut config = BehavioralConfig::default();
        config.min_observations = 10;
        config.max_deviation = 2.0;
        let counter = BehavioralCounter::new(config);

        // Add values around 100
        for _ in 0..20 {
            counter.add_observation(100);
        }

        // Test bounds
        assert!(counter.get_last_lower_bound() < 100);
        assert!(counter.get_last_upper_bound() > 100);

        // Test anomaly detection
        assert!(counter.add_observation(200));  // Above upper bound
        assert!(counter.add_observation(0));    // Below lower bound
        assert!(!counter.add_observation(100)); // Within bounds
    }
}
