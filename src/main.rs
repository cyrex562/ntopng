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

mod active_host_walker_info;
mod address_resolution;
mod address_tree;
mod aggregated_flow_stats;
mod alert;
mod alert_counter;
mod alert_fifo_item;
mod alert_fifo_queue;
mod alert_store;
mod alerts_queue;
mod alertable_entity;
mod autonomous_system;
mod autonomous_system_hash;
mod behavioral_counter;
mod bitmap;

use std::env;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use ctrlc;

#[cfg(target_os = "windows")]
use winapi::um::winsock2::{WSADATA, WSAStartup, MAKEWORD};

#[derive(PartialEq)]
enum AfterShutdownAction {
    Nop,
    Reboot,
    Poweroff,
    RestartSelf,
}

static mut AFTER_SHUTDOWN_ACTION: AfterShutdownAction = AfterShutdownAction::Nop;
static mut TRACE_NEW_DELETE: bool = false;

#[cfg(target_os = "windows")]
fn init_winsock32() -> Result<(), String> {
    unsafe {
        let mut wsa_data: WSADATA = std::mem::zeroed();
        let version = MAKEWORD(2, 0);
        
        match WSAStartup(version, &mut wsa_data) {
            0 => Ok(()),
            err => Err(format!("FATAL ERROR: unable to initialize Winsock 2.x. Error code: {}", err))
        }
    }
}

fn setup_signal_handlers(shutdown_flag: Arc<AtomicBool>) {
    ctrlc::set_handler(move || {
        static mut CALLED: bool = false;
        
        unsafe {
            if CALLED {
                println!("Ok I am leaving now");
                process::exit(0);
            } else {
                println!("Shutting down...");
                shutdown_flag.store(true, Ordering::SeqCst);
                CALLED = true;
            }
        }
    }).expect("Error setting up signal handlers");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    
    #[cfg(target_os = "windows")]
    init_winsock32()?;

    // Initialize SQLite for multi-threading
    #[cfg(not(target_os = "windows"))]
    {
        unsafe {
            sqlite3_shutdown();
            if sqlite3_config(SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK {
                eprintln!("Unable to set SQLITE_CONFIG_MULTITHREAD for sqlite, exiting.");
                process::exit(1);
            }
            sqlite3_initialize();
        }
    }

    // Create Ntop instance
    let ntop = Ntop::new(&args[0]).expect("Failed to create Ntop instance");
    let prefs = Prefs::new(&ntop).expect("Failed to create Prefs instance");

    // Load preferences
    #[cfg(not(target_os = "windows"))]
    if args.len() >= 2 && !args[1].starts_with('-') {
        prefs.load_from_file(&args[1])?;
        if args.len() > 2 {
            prefs.load_from_cli(&args)?;
        }
    } else {
        prefs.load_from_cli(&args)?;
    }

    #[cfg(target_os = "windows")]
    prefs.load_from_cli(&args)?;

    // Create working directory
    fs::create_dir_all(ntop.get_working_dir())?;

    #[cfg(not(target_os = "windows"))]
    ntop.lock_ntop_instance()?;

    ntop.register_prefs(&prefs, false);
    prefs.reload_prefs_from_redis();

    // Run boot script
    if let Ok(boot_activity) = ThreadedActivity::new(BOOT_SCRIPT_PATH) {
        boot_activity.run_system_script(SystemTime::now())?;
    }

    // Register network interfaces
    prefs.register_network_interfaces();

    if prefs.get_num_user_specified_interfaces() == 0 {
        prefs.add_default_interfaces();
    }

    prefs.validate();

    // Setup signal handlers
    setup_signal_handlers(Arc::clone(&shutdown_flag));

    // Main loop
    ntop.start()?;

    println!("Terminating...");

    // Cleanup
    ntop.shutdown_all()?;
    ntop.run_shutdown_tasks()?;

    #[cfg(target_os = "linux")]
    unsafe {
        match AFTER_SHUTDOWN_ACTION {
            AfterShutdownAction::Reboot => {
                std::process::Command::new("systemctl")
                    .arg("reboot")
                    .spawn()?;
            },
            AfterShutdownAction::Poweroff => {
                std::process::Command::new("systemctl")
                    .arg("start")
                    .arg("systemd-poweroff")
                    .spawn()?;
            },
            AfterShutdownAction::RestartSelf => {
                return Ok(());  // Return 1 to force systemd restart
            },
            AfterShutdownAction::Nop => {},
        }
    }

    Ok(())
}
