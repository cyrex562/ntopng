/*
 * (C) 2014-25 - ntop.org
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

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use crate::alert_fifo_item::AlertFifoItem;

/// A thread-safe FIFO queue implementation for AlertFifoItem
#[derive(Debug)]
pub struct AlertFifoQueue {
    /// The underlying queue implementation
    queue: Mutex<VecDeque<Arc<AlertFifoItem>>>,
    
    /// Maximum size of the queue
    max_size: usize,
    
    /// Number of items that have been enqueued
    num_enqueued: AtomicU64,
    
    /// Number of items that have been dequeued
    num_dequeued: AtomicU64,
    
    /// Number of items that were dropped due to queue being full
    num_dropped: AtomicU64,
}

impl AlertFifoQueue {
    /// Creates a new AlertFifoQueue with the specified maximum size
    pub fn new(queue_size: u32) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(queue_size as usize)),
            max_size: queue_size as usize,
            num_enqueued: AtomicU64::new(0),
            num_dequeued: AtomicU64::new(0),
            num_dropped: AtomicU64::new(0),
        }
    }

    /// Attempts to enqueue an AlertFifoItem
    /// 
    /// Returns true if the item was successfully enqueued,
    /// false if the queue was full and the item was dropped
    pub fn enqueue(&self, item: AlertFifoItem) -> bool {
        let mut queue = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if queue.len() >= self.max_size {
            self.num_dropped.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            queue.push_back(Arc::new(item));
            self.num_enqueued.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    /// Attempts to dequeue an AlertFifoItem
    /// 
    /// Returns Some(AlertFifoItem) if an item was available,
    /// None if the queue was empty
    pub fn dequeue(&self) -> Option<Arc<AlertFifoItem>> {
        let mut queue = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(item) = queue.pop_front() {
            self.num_dequeued.fetch_add(1, Ordering::Relaxed);
            Some(item)
        } else {
            None
        }
    }

    /// Returns the current length of the queue
    pub fn len(&self) -> usize {
        let queue = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        queue.len()
    }

    /// Returns true if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if the queue is full
    pub fn is_full(&self) -> bool {
        self.len() >= self.max_size
    }

    /// Returns the maximum size of the queue
    pub fn capacity(&self) -> usize {
        self.max_size
    }

    /// Returns the number of items that have been enqueued
    pub fn num_enqueued(&self) -> u64 {
        self.num_enqueued.load(Ordering::Relaxed)
    }

    /// Returns the number of items that have been dequeued
    pub fn num_dequeued(&self) -> u64 {
        self.num_dequeued.load(Ordering::Relaxed)
    }

    /// Returns the number of items that were dropped
    pub fn num_dropped(&self) -> u64 {
        self.num_dropped.load(Ordering::Relaxed)
    }
}

impl Drop for AlertFifoQueue {
    fn drop(&mut self) {
        // Clear the queue
        if let Ok(mut queue) = self.queue.lock() {
            queue.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alertable_entity::{AlertEntity, AlertLevel};
    use crate::alert_fifo_item::AlertCategory;

    #[test]
    fn test_queue_basic_operations() {
        let queue = AlertFifoQueue::new(2);
        assert!(queue.is_empty());
        assert_eq!(queue.capacity(), 2);

        let item1 = AlertFifoItem {
            alert_entity: AlertEntity::Host,
            alert_severity: AlertLevel::Warning,
            alert_category: AlertCategory::Security,
            alert: String::from("test1"),
            score: 50,
            alert_id: 1,
            host: Default::default(),
            flow: Default::default(),
        };

        let item2 = AlertFifoItem {
            alert_entity: AlertEntity::Host,
            alert_severity: AlertLevel::Error,
            alert_category: AlertCategory::Security,
            alert: String::from("test2"),
            score: 75,
            alert_id: 2,
            host: Default::default(),
            flow: Default::default(),
        };

        // Test enqueue
        assert!(queue.enqueue(item1));
        assert!(queue.enqueue(item2));
        assert!(queue.is_full());

        // Test dequeue
        if let Some(item) = queue.dequeue() {
            assert_eq!(item.alert, "test1");
            assert_eq!(item.score, 50);
        } else {
            panic!("Expected item not found");
        }

        if let Some(item) = queue.dequeue() {
            assert_eq!(item.alert, "test2");
            assert_eq!(item.score, 75);
        } else {
            panic!("Expected item not found");
        }

        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_overflow() {
        let queue = AlertFifoQueue::new(1);
        
        let item1 = AlertFifoItem::default();
        let item2 = AlertFifoItem::default();

        assert!(queue.enqueue(item1));
        assert!(!queue.enqueue(item2)); // Should fail as queue is full
        assert_eq!(queue.num_dropped(), 1);
    }

    #[test]
    fn test_queue_counters() {
        let queue = AlertFifoQueue::new(2);
        
        let item1 = AlertFifoItem::default();
        let item2 = AlertFifoItem::default();
        let item3 = AlertFifoItem::default();

        queue.enqueue(item1);
        queue.enqueue(item2);
        assert!(!queue.enqueue(item3)); // Should be dropped

        assert_eq!(queue.num_enqueued(), 2);
        assert_eq!(queue.num_dropped(), 1);

        queue.dequeue();
        assert_eq!(queue.num_dequeued(), 1);
    }
}
