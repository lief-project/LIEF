//! LIEF's logging API
//!
//! This module contains function to tweak or use LIEF's logging mechanisms
//!
//!
//! ```
//! use lief::logging;
//!
//! logging::set_level(logging::Level::DEBUG);
//! logging::log(logging::Level::DEBUG, "Hi!");
//! ```

use lief_ffi as ffi;

use std::path::Path;
use std::convert::{From, Into};

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The different levels of log
pub enum Level {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERR,
    CRITICAL,
    UNKNOWN(u32),
}

impl From<u32> for Level {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Level::TRACE,
            0x00000001 => Level::DEBUG,
            0x00000002 => Level::INFO,
            0x00000003 => Level::WARN,
            0x00000004 => Level::ERR,
            0x00000005 => Level::CRITICAL,
            _ => Level::UNKNOWN(value),
        }
    }
}

impl Into<u32> for Level {
    fn into(self) -> u32 {
        match self {
            Level::TRACE => 0x00000000,
            Level::DEBUG => 0x00000001,
            Level::INFO => 0x00000002,
            Level::WARN => 0x00000003,
            Level::ERR => 0x00000004,
            Level::CRITICAL => 0x00000005,
            Level::UNKNOWN(_) => 0x00000002, // INFO
        }
    }
}

/// Reset the current logger
pub fn reset() {
    ffi::LIEF_Logging::reset()
}

/// Prevent any log message from being printed
pub fn disable() {
    ffi::LIEF_Logging::disable()
}

/// Enable the logger
pub fn enable() {
    ffi::LIEF_Logging::enable()
}

/// Change the logging level
///
/// ```
/// set_level(Level::INFO)
/// ```
pub fn set_level(level: Level) {
    ffi::LIEF_Logging::set_level(level.into())
}
/// Switch to a file-based logger (instead of stderr-based)
///
/// ```
/// let mut tmp = env::temp_dir();
/// tmp.push("lief_log.log");
/// logging::set_path(dir.as_path());
/// ```
pub fn set_path(path: &Path) {
    ffi::LIEF_Logging::set_path(path.to_str().expect("Can't convert into string"))
}

/// Log a message with the logger
pub fn log(level: Level, message: &str) {
    ffi::LIEF_Logging::log(level.into(), message)
}



