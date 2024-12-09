use lief_ffi as ffi;

/// Structure used to configure the [`crate::elf::Binary::write_with_config`] operation
#[derive(Debug)]
pub struct Config {
    /// Rebuild `DT_HASH`
    pub dt_hash: bool,

    /// Rebuild `DT_STRTAB`
    pub dyn_str: bool,

    /// Rebuild `PT_DYNAMIC` segment
    pub dynamic_section: bool,

    /// Rebuild `DT_FINI_ARRAY`
    pub fini_array: bool,

    /// Rebuild `DT_GNU_HASH`
    pub gnu_hash: bool,

    /// Rebuild `DT_INIT_ARRAY`
    pub init_array: bool,

    /// Rebuild `PT_INTERPRETER`
    pub interpreter: bool,

    /// Rebuild `DT_JMPREL`
    pub jmprel: bool,

    /// Rebuild notes sections
    pub notes: bool,

    /// Rebuild `DT_PREINIT_ARRAY`
    pub preinit_array: bool,

    /// Rebuild `DT_RELR`
    pub relr: bool,

    /// Rebuild `DT_ANDROID_REL[A]`
    pub android_rela: bool,

    /// Rebuild `DT_REL[A]`
    pub rela: bool,

    /// Rebuild `.symtab`
    pub static_symtab: bool,

    /// Rebuild `DT_VERDEF`
    pub sym_verdef: bool,

    /// Rebuild `DT_VERNEED`
    pub sym_verneed: bool,

    /// Rebuild `DT_VERSYM`
    pub sym_versym: bool,

    /// Rebuild `DT_SYMTAB`
    pub symtab: bool,

    /// Rebuild the Coredump notes
    pub coredump_notes: bool,

    /// Force to relocating all the ELF structures that are supported by LIEF (mostly for testing)
    pub force_relocate: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            dt_hash: true,
            dyn_str: true,
            dynamic_section: true,
            fini_array: true,
            gnu_hash: true,
            init_array: true,
            interpreter: true,
            jmprel: true,
            notes: false,
            preinit_array: true,
            relr: true,
            android_rela: true,
            rela: true,
            static_symtab: true,
            sym_verdef: true,
            sym_verneed: true,
            sym_versym: true,
            symtab: true,
            coredump_notes: true,
            force_relocate: false,
        }
    }
}

impl Config {
    #[doc(hidden)]
    pub fn to_ffi(&self) -> ffi::ELF_Binary_write_config_t {
        ffi::ELF_Binary_write_config_t {
            dt_hash: self.dt_hash,
            dyn_str: self.dyn_str,
            dynamic_section: self.dynamic_section,
            fini_array: self.fini_array,
            gnu_hash: self.gnu_hash,
            init_array: self.init_array,
            interpreter: self.interpreter,
            jmprel: self.jmprel,
            notes: self.notes,
            preinit_array: self.preinit_array,
            relr: self.relr,
            android_rela: self.android_rela,
            rela: self.rela,
            static_symtab: self.static_symtab,
            sym_verdef: self.sym_verdef,
            sym_verneed: self.sym_verneed,
            sym_versym: self.sym_versym,
            symtab: self.symtab,
            coredump_notes: self.coredump_notes,
            force_relocate: self.force_relocate,
        }
    }
}


