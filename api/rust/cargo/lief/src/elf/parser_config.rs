use lief_ffi as ffi;

/// This structure is used to tweak the ELF parser: [`crate::elf::Binary::parse_with_config`]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// Whether relocations (including plt-like relocations) should be parsed.
    pub parse_relocations: bool,

    /// Whether dynamic symbols (those from `.dynsym`) should be parsed
    pub parse_dyn_symbols: bool,

    /// Whether debug symbols (those from `.symtab`) should be parsed
    pub parse_symtab_symbols: bool,

    /// Whether versioning symbols should be parsed
    pub parse_symbol_versions: bool,

    /// Whether ELF notes  information should be parsed
    pub parse_notes: bool,

    /// Whether the overlay data should be parsed
    pub parse_overlay: bool,

    /// The method used to count the number of dynamic symbols
    pub count_mtd: DynSymCount,

    /// Memory page size if the binary uses a non-standard value.
    ///
    /// For instance, SPARCV9 binary can use page size from 0x2000 to 0x100000.
    pub page_size: u64,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            parse_relocations: true,
            parse_dyn_symbols: true,
            parse_symtab_symbols: true,
            parse_symbol_versions: true,
            parse_notes: true,
            parse_overlay: true,
            count_mtd: DynSymCount::AUTO,
            page_size: 0,
        }
    }
}

impl Config {
    #[doc(hidden)]
    pub fn to_ffi(&self) -> cxx::UniquePtr<ffi::ELF_ParserConfig> {
        let mut ptr = ffi::ELF_ParserConfig::create();
        ptr.pin_mut().set_parse_relocations(self.parse_relocations);
        ptr.pin_mut().set_parse_dyn_symbols(self.parse_dyn_symbols);
        ptr.pin_mut().set_parse_symtab_symbols(self.parse_symtab_symbols);
        ptr.pin_mut().set_parse_symbol_versions(self.parse_symbol_versions);
        ptr.pin_mut().set_parse_notes(self.parse_notes);
        ptr.pin_mut().set_parse_overlay(self.parse_overlay);
        ptr.pin_mut().set_count_mtd(self.count_mtd.into());
        ptr.pin_mut().set_page_size(self.page_size);
        ptr
    }
}


/// Enum that describes the different methods that can be used by the parser to identity
/// the number of dynamic symbols
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum DynSymCount {
    /// Automatic detection
    AUTO,

    /// Count based on sections (not very reliable
    SECTION,

    /// Count based on hash table (reliable)
    HASH,

    /// Count based on PLT/GOT relocations (very reliable but not accurate)
    RELOCATIONS,

    UNKNOWN(u32),
}

impl From<u32> for DynSymCount {
    fn from(value: u32) -> Self {
        match value {
            0 => DynSymCount::AUTO,
            1 => DynSymCount::SECTION,
            2 => DynSymCount::HASH,
            3 => DynSymCount::RELOCATIONS,
            _ => DynSymCount::UNKNOWN(value),
        }
    }
}

impl From<DynSymCount> for u32 {
    fn from(value: DynSymCount) -> u32 {
        match value {
            DynSymCount::AUTO => 0,
            DynSymCount::SECTION => 1,
            DynSymCount::HASH => 2,
            DynSymCount::RELOCATIONS => 3,
            DynSymCount::UNKNOWN(value) => value,
        }
    }
}
