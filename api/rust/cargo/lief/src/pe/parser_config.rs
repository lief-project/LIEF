use lief_ffi as ffi;

/// This structure is used to tweak the PE parser: [`lief::pe::Binary::parse_with_config`]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// Parse PE authenticode signature
    pub parse_signature: bool,

    /// Parse PE Exports Directory
    pub parse_exports: bool,

    /// Parse PE Import Directory
    pub parse_imports: bool,

    /// Parse PE resources tree
    pub parse_rsrc: bool,

    /// Parse PE relocations
    pub parse_reloc: bool,

    /// Whether it should parse in-depth exceptions metadata.
    ///
    /// This option is set to off by default since it can introduce a certain
    /// overhead.
    pub parse_exceptions: bool,

    /// Whether it should parse nested ARM64X binary
    ///
    /// This option is set to off by default since it can introduce a certain
    /// overhead.
    pub parse_arm64x_binary: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            parse_signature: true,
            parse_exports: true,
            parse_imports: true,
            parse_rsrc: true,
            parse_reloc: true,
            parse_exceptions: false,
            parse_arm64x_binary: false,
        }
    }
}

impl Config {
    #[doc(hidden)]
    pub fn to_ffi(&self) -> cxx::UniquePtr<ffi::PE_ParserConfig> {
        let mut ptr = ffi::PE_ParserConfig::create();
        ptr.pin_mut().set_parse_signature(self.parse_signature);
        ptr.pin_mut().set_parse_exports(self.parse_exports);
        ptr.pin_mut().set_parse_imports(self.parse_imports);
        ptr.pin_mut().set_parse_rsrc(self.parse_rsrc);
        ptr.pin_mut().set_parse_reloc(self.parse_reloc);
        ptr.pin_mut().set_parse_exceptions(self.parse_exceptions);
        ptr.pin_mut().set_parse_arm64x_binary(self.parse_arm64x_binary);
        ptr
    }

    /// Configuration with **all** the options enabled
    pub fn with_all_options() -> Self {
        Self {
            parse_signature: true,
            parse_exports: true,
            parse_imports: true,
            parse_rsrc: true,
            parse_reloc: true,
            parse_exceptions: true,
            parse_arm64x_binary: true,
        }
    }
}
