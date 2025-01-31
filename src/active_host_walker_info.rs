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

use mlua::{Lua, Table, Value};
use std::ffi::CStr;
use std::os::raw::c_char;

pub struct ActiveHostWalkerInfo {
    name: String,
    label: String,
    x: i64,
    y: i64,
    z: u64,
}

impl ActiveHostWalkerInfo {
    pub fn new(name: *const c_char, label: *const c_char, x: i64, y: i64, z: u64) -> Self {
        let name = unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned();
        let label = unsafe { CStr::from_ptr(label) }
            .to_string_lossy()
            .into_owned();
            
        Self {
            name,
            label,
            x,
            y,
            z,
        }
    }

    #[inline]
    pub fn get_z(&self) -> u64 {
        self.z
    }

    pub fn to_lua(&self, lua: &Lua, tree_map_mode: bool) -> mlua::Result<Table> {
        let table = lua.create_table()?;

        if tree_map_mode {
            table.set("x", self.name.as_str())?;
            table.set("y", self.z)?;
            table.set("label", self.label.as_str())?;
        } else {
            // Create meta table
            let meta = lua.create_table()?;
            meta.set("label", self.label.as_str())?;
            
            let url_query = format!("host={}", self.name);
            meta.set("url_query", url_query)?;
            
            table.set("meta", meta)?;

            // Set other values
            table.set("x", self.x)?;
            table.set("y", self.y)?;
            table.set("z", self.z)?;
        }

        Ok(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_active_host_walker_info() {
        let name = CString::new("test_host").unwrap();
        let label = CString::new("Test Label").unwrap();
        
        let info = ActiveHostWalkerInfo::new(
            name.as_ptr(),
            label.as_ptr(),
            10,
            20,
            30
        );

        assert_eq!(info.get_z(), 30);
        assert_eq!(info.name, "test_host");
        assert_eq!(info.label, "Test Label");
        assert_eq!(info.x, 10);
        assert_eq!(info.y, 20);
    }

    #[test]
    fn test_lua_conversion() -> mlua::Result<()> {
        let lua = Lua::new();
        let name = CString::new("test_host").unwrap();
        let label = CString::new("Test Label").unwrap();
        
        let info = ActiveHostWalkerInfo::new(
            name.as_ptr(),
            label.as_ptr(),
            10,
            20,
            30
        );

        // Test tree map mode
        let table = info.to_lua(&lua, true)?;
        assert_eq!(table.get::<_, String>("x")?, "test_host");
        assert_eq!(table.get::<_, u64>("y")?, 30);
        assert_eq!(table.get::<_, String>("label")?, "Test Label");

        // Test normal mode
        let table = info.to_lua(&lua, false)?;
        assert_eq!(table.get::<_, i64>("x")?, 10);
        assert_eq!(table.get::<_, i64>("y")?, 20);
        assert_eq!(table.get::<_, u64>("z")?, 30);

        let meta: Table = table.get("meta")?;
        assert_eq!(meta.get::<_, String>("label")?, "Test Label");
        assert_eq!(meta.get::<_, String>("url_query")?, "host=test_host");

        Ok(())
    }
}
