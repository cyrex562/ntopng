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

use std::ops::{BitOr, BitOrAssign};
use std::fmt::{self, Debug, Display};
use serde::{Serialize, Deserialize};
use mlua::{Lua, Table, Value};

/// A generic bitmap implementation that supports various integer types
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Bitmap<T> 
where
    T: BitOr<Output = T> + BitOrAssign + Copy + Default + 'static,
{
    bitmap: T,
}

impl<T> Bitmap<T> 
where
    T: BitOr<Output = T> + BitOrAssign + Copy + Default + 'static,
{
    /// Creates a new empty bitmap
    pub fn new() -> Self {
        Self { bitmap: T::default() }
    }

    /// Returns the number of bits in the bitmap
    pub const fn num_bits() -> usize {
        std::mem::size_of::<T>() * 8
    }

    /// Resets all bits to zero
    pub fn reset(&mut self) {
        self.bitmap = T::default();
    }

    /// Sets the bit at the given index
    /// 
    /// # Panics
    /// 
    /// Panics if the index is out of bounds (>= num_bits())
    pub fn set_bit(&mut self, id: u8) {
        assert!((id as usize) < Self::num_bits(), "Bit index out of bounds");
        // Safe because we checked bounds
        self.bitmap |= unsafe { std::mem::transmute_copy(&(1 << id)) };
    }

    /// Clears the bit at the given index
    /// 
    /// # Panics
    /// 
    /// Panics if the index is out of bounds (>= num_bits())
    pub fn clear_bit(&mut self, id: u8) {
        assert!((id as usize) < Self::num_bits(), "Bit index out of bounds");
        // Safe because we checked bounds
        self.bitmap &= unsafe { std::mem::transmute_copy(&!(1 << id)) };
    }

    /// Returns true if the bit at the given index is set
    /// 
    /// # Panics
    /// 
    /// Panics if the index is out of bounds (>= num_bits())
    pub fn is_set_bit(&self, id: u8) -> bool {
        assert!((id as usize) < Self::num_bits(), "Bit index out of bounds");
        // Safe because we checked bounds
        (self.bitmap & unsafe { std::mem::transmute_copy(&(1 << id)) }) != T::default()
    }

    /// Performs a bitwise OR with another bitmap
    pub fn bitmap_or(&mut self, other: &Self) {
        self.bitmap |= other.bitmap;
    }

    /// Sets this bitmap to the value of another bitmap
    pub fn set(&mut self, other: &Self) {
        self.bitmap = other.bitmap;
    }

    /// Returns true if this bitmap equals another bitmap
    pub fn equal(&self, other: &Self) -> bool {
        self.bitmap == other.bitmap
    }

    /// Returns an iterator over the set bits in the bitmap
    pub fn iter_set_bits(&self) -> SetBitsIterator<T> {
        SetBitsIterator {
            bitmap: *self,
            current_bit: 0,
        }
    }

    /// Returns the raw bitmap value
    pub fn as_raw(&self) -> T {
        self.bitmap
    }

    /// Creates a bitmap from a raw value
    pub fn from_raw(raw: T) -> Self {
        Self { bitmap: raw }
    }

    /// Converts the bitmap to a Lua table
    pub fn to_lua<'lua>(&self, lua: &'lua Lua, label: &str) -> mlua::Result<Table<'lua>> {
        let table = lua.create_table()?;
        let risks = lua.create_table()?;

        for i in 0..Self::num_bits() {
            if self.is_set_bit(i as u8) {
                risks.set(i + 1, true)?;
            }
        }

        table.set(label, risks)?;
        Ok(table)
    }
}

/// Iterator over set bits in a bitmap
pub struct SetBitsIterator<T> {
    bitmap: Bitmap<T>,
    current_bit: u8,
}

impl<T> Iterator for SetBitsIterator<T>
where
    T: BitOr<Output = T> + BitOrAssign + Copy + Default + 'static,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        while (self.current_bit as usize) < Bitmap::<T>::num_bits() {
            let bit = self.current_bit;
            self.current_bit += 1;
            if self.bitmap.is_set_bit(bit) {
                return Some(bit);
            }
        }
        None
    }
}

impl<T> Default for Bitmap<T>
where
    T: BitOr<Output = T> + BitOrAssign + Copy + Default + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Debug for Bitmap<T>
where
    T: BitOr<Output = T> + BitOrAssign + Copy + Default + fmt::Binary + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bitmap({:#b})", self.bitmap)
    }
}

impl<T> Display for Bitmap<T>
where
    T: BitOr<Output = T> + BitOrAssign + Copy + Default + fmt::Binary + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#b}", self.bitmap)
    }
}

/// Common type aliases for different bitmap sizes
pub type Bitmap8 = Bitmap<u8>;
pub type Bitmap16 = Bitmap<u16>;
pub type Bitmap32 = Bitmap<u32>;
pub type Bitmap64 = Bitmap<u64>;
pub type Bitmap128 = Bitmap<u128>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_basic() {
        let mut bitmap = Bitmap32::new();
        assert_eq!(bitmap.as_raw(), 0);

        bitmap.set_bit(0);
        assert!(bitmap.is_set_bit(0));
        assert!(!bitmap.is_set_bit(1));

        bitmap.set_bit(31);
        assert!(bitmap.is_set_bit(31));

        bitmap.clear_bit(0);
        assert!(!bitmap.is_set_bit(0));
    }

    #[test]
    fn test_bitmap_operations() {
        let mut bitmap1 = Bitmap32::new();
        let mut bitmap2 = Bitmap32::new();

        bitmap1.set_bit(0);
        bitmap2.set_bit(1);

        bitmap1.bitmap_or(&bitmap2);
        assert!(bitmap1.is_set_bit(0));
        assert!(bitmap1.is_set_bit(1));
    }

    #[test]
    fn test_bitmap_iterator() {
        let mut bitmap = Bitmap32::new();
        bitmap.set_bit(0);
        bitmap.set_bit(2);
        bitmap.set_bit(4);

        let bits: Vec<u8> = bitmap.iter_set_bits().collect();
        assert_eq!(bits, vec![0, 2, 4]);
    }

    #[test]
    #[should_panic(expected = "Bit index out of bounds")]
    fn test_bitmap_out_of_bounds() {
        let mut bitmap = Bitmap8::new();
        bitmap.set_bit(8); // Should panic
    }

    #[test]
    fn test_bitmap_lua() -> mlua::Result<()> {
        let lua = Lua::new();
        let mut bitmap = Bitmap32::new();
        bitmap.set_bit(0);
        bitmap.set_bit(2);

        let table = bitmap.to_lua(&lua, "risks")?;
        let risks: Table = table.get("risks")?;
        
        assert_eq!(risks.get::<_, bool>(1)?, true);  // Lua is 1-indexed
        assert_eq!(risks.get::<_, bool>(2)?, false);
        assert_eq!(risks.get::<_, bool>(3)?, true);
        
        Ok(())
    }
}
