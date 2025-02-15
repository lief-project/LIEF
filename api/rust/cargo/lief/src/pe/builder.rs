use lief_ffi as ffi;

/// Structure used to configure the [`crate::pe::Binary::write_with_config`] operation
///
/// The default value of these attributes is set to `false` if the
/// operation modifies the binary layout even though nothing changed.
/// For instance, building the import table **always** requires relocating the
/// table to another place. Thus, the default value is false and must
/// be explicitly set to true.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// Whether the builder should reconstruct the imports table. This option should be turned on
    /// if you modify imports.
    ///
    /// Please check LIEF website for more details
    pub imports: bool,

    /// Whether the builder should reconstruct the export table This option should be turned on if
    /// you modify exports.
    ///
    /// Please check LIEF website for more details
    pub exports: bool,

    /// Whether the builder should regenerate the resources tree
    pub resources: bool,

    /// Whether the builder should regenerate relocations
    pub relocations: bool,

    /// Whether the builder should regenerate the load config
    pub load_configuration: bool,

    /// Whether the builder should regenerate the TLS info
    pub tls: bool,

    /// Whether the builder should write back any overlay data
    pub overlay: bool,

    /// Whether the builder should regenerate debug entries
    pub debug: bool,

    /// Whether the builder should write back dos stub (including the rich
    /// header)
    pub dos_stub: bool,

    /// If the resources tree needs to be relocated, this defines the name of
    /// the new section that contains the relocated tree.
    pub rsrc_section: String,

    /// Section that holds the relocated import table (IAT/ILT)
    pub idata_section: String,

    /// Section that holds the relocated TLS info
    pub tls_section: String,

    /// Section that holds the relocated relocations
    pub reloc_section: String,

    /// Section that holds the export table
    pub export_section: String,

    /// Section that holds the debug entries
    pub debug_section: String,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            imports: false,
            exports: false,
            resources: true,
            relocations: true,
            load_configuration: true,
            tls: true,
            overlay: true,
            debug: true,
            dos_stub: true,
            rsrc_section: ".rsrc".to_string(),
            idata_section: ".idata".to_string(),
            tls_section: ".tls".to_string(),
            reloc_section: ".reloc".to_string(),
            export_section: ".edata".to_string(),
            debug_section: ".debug".to_string(),
        }
    }
}

impl Config {
    #[doc(hidden)]
    pub fn to_ffi(&self) -> cxx::UniquePtr<ffi::PE_Binary_write_config_t> {
        let mut ptr = ffi::PE_Binary_write_config_t::create();
        ptr.pin_mut().set_import(self.imports);
        ptr.pin_mut().set_exports(self.exports);
        ptr.pin_mut().set_resources(self.resources);
        ptr.pin_mut().set_relocations(self.relocations);
        ptr.pin_mut().set_load_config(self.load_configuration);
        ptr.pin_mut().set_tls(self.tls);
        ptr.pin_mut().set_overlay(self.overlay);
        ptr.pin_mut().set_dos_stub(self.dos_stub);
        ptr.pin_mut().set_rsrc_section(&self.rsrc_section);
        ptr.pin_mut().set_idata_section(&self.idata_section);
        ptr.pin_mut().set_tls_section(&self.tls_section);
        ptr.pin_mut().set_reloc_section(&self.reloc_section);
        ptr.pin_mut().set_export_section(&self.export_section);
        ptr.pin_mut().set_debug_section(&self.debug_section);
        ptr
    }
}
