use lief_ffi as ffi;

/// Structure used to configure the [`crate::macho::Binary::write_with_config`] operation
#[derive(Debug)]
pub struct Config {
    /// Rebuild the `__LINKEDIT` segment
    pub linkedit: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            linkedit: true,
        }
    }
}

impl Config {
    #[doc(hidden)]
    pub fn to_ffi(&self) -> ffi::MachO_Binary_write_config_t {
        ffi::MachO_Binary_write_config_t {
            linkedit: self.linkedit,
        }
    }
}
