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

use std::convert::{From, Into};
use std::path::Path;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The different levels of log
pub enum Level {
    OFF,
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
            0x00000000 => Level::OFF,
            0x00000001 => Level::TRACE,
            0x00000002 => Level::DEBUG,
            0x00000003 => Level::INFO,
            0x00000004 => Level::WARN,
            0x00000005 => Level::ERR,
            0x00000006 => Level::CRITICAL,
            _ => Level::UNKNOWN(value),
        }
    }
}

impl From<Level> for u32 {
    fn from(value: Level) -> Self {
        match value {
            Level::OFF => 0x00000000,
            Level::TRACE => 0x00000001,
            Level::DEBUG => 0x00000002,
            Level::INFO => 0x00000003,
            Level::WARN => 0x00000004,
            Level::ERR => 0x00000005,
            Level::CRITICAL => 0x00000006,
            Level::UNKNOWN(_) => 0x00000003, // INFO
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
pub fn set_path<P: AsRef<Path>>(path: P) {
    ffi::LIEF_Logging::set_path(path.as_ref().to_str().expect("Can't convert into string"))
}

/// Log a message with the logger
pub fn log(level: Level, message: &str) {
    ffi::LIEF_Logging::log(level.into(), message)
}

/// Return the current logging level
pub fn get_level() -> Level {
    Level::from(ffi::LIEF_Logging::get_level())
}

/// RAII-like scoped log level.
///
///
/// ```
/// use lief::logging;
///
/// logging::set_level(logging::Level::INFO);
///
/// {
///     let _scoped = logging::Scoped::new(logging::Level::DEBUG);
///     // Log level is now DEBUG
/// }
/// // Log level is restored to INFO
/// ```
pub struct Scoped {
    inner: cxx::UniquePtr<ffi::LIEF_Logging_Scoped>,
}

impl Scoped {
    /// Create a new scoped log level. The current log level is saved and
    /// replaced with the provided `level`. When this value is dropped, the
    /// original level is restored.
    pub fn new(level: Level) -> Self {
        Self {
            inner: ffi::LIEF_Logging_Scoped::create(level.into()),
        }
    }

    /// Change the log level within this scope
    pub fn set_level(&self, level: Level) {
        self.inner.set_level(level.into())
    }

    /// Reset the log level to the value it had before this scope was created
    pub fn reset(&mut self) {
        self.inner.pin_mut().reset()
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lief_log {
    ($level: expr) => {
        lief::logging::log($level, "")
    };
    ($level: expr, $($arg:tt)*) => {{
        lief::logging::log($level, &format!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_dbg {
    ($($args:tt)*) => {
        $crate::__lief_log!(lief::logging::Level::DEBUG, $($args)*)
    };
}

#[macro_export]
macro_rules! log_info {
    ($($args:tt)*) => {
        $crate::__lief_log!(lief::logging::Level::INFO, $($args)*)
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($args:tt)*) => {
        $crate::__lief_log!(lief::logging::Level::WARN, $($args)*)
    };
}

#[macro_export]
macro_rules! log_err {
    ($($args:tt)*) => {
        $crate::__lief_log!(lief::logging::Level::ERR, $($args)*)
    };
}
