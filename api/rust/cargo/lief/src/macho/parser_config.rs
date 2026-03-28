use lief_ffi as ffi;

/// This structure is used to tweak the MachO parser:
/// [`crate::macho::FatBinary::parse_with_config`]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// Parse the Dyld export trie
    pub parse_dyld_exports: bool,

    /// Parse the Dyld binding opcodes
    pub parse_dyld_bindings: bool,

    /// Parse the Dyld rebase opcodes
    pub parse_dyld_rebases: bool,

    /// Whether the overlay data should be parsed
    pub parse_overlay: bool,

    /// When parsing Mach-O from memory, this option
    /// can be used to *undo* relocations and symbols bindings.
    ///
    /// When activated, this option requires `parse_dyld_bindings`
    /// and `parse_dyld_rebases` to be enabled.
    pub fix_from_memory: bool,

    /// Whether the binary is coming/extracted from Dyld shared cache
    pub from_dyld_shared_cache: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            parse_dyld_exports: true,
            parse_dyld_bindings: true,
            parse_dyld_rebases: true,
            parse_overlay: true,
            fix_from_memory: false,
            from_dyld_shared_cache: false,
        }
    }
}

impl Config {
    #[doc(hidden)]
    pub fn to_ffi(&self) -> cxx::UniquePtr<ffi::MachO_ParserConfig> {
        let mut ptr = ffi::MachO_ParserConfig::create();
        ptr.pin_mut().set_parse_dyld_exports(self.parse_dyld_exports);
        ptr.pin_mut().set_parse_dyld_bindings(self.parse_dyld_bindings);
        ptr.pin_mut().set_parse_dyld_rebases(self.parse_dyld_rebases);
        ptr.pin_mut().set_parse_overlay(self.parse_overlay);
        ptr.pin_mut().set_fix_from_memory(self.fix_from_memory);
        ptr.pin_mut().set_from_dyld_shared_cache(self.from_dyld_shared_cache);
        ptr
    }

    /// Configuration that parses all supported MachO structures (deep parse).
    pub fn deep() -> Self {
        Self::default()
    }

    /// Configuration for a quick parse of the most important MachO structures.
    pub fn quick() -> Self {
        Self {
            parse_dyld_exports: true,
            parse_dyld_bindings: false,
            parse_dyld_rebases: false,
            parse_overlay: true,
            fix_from_memory: false,
            from_dyld_shared_cache: false,
        }
    }
}
