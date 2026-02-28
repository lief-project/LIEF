use lief_ffi as ffi;

/// This structure is used to configure the behavior of the PE Parser: [`crate::pe::Binary::parse_with_config`]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// Whether to parse the PE Authenticode signature.
    pub parse_signature: bool,

    /// Whether to parse the PE Export Directory.
    pub parse_exports: bool,

    /// Whether to parse the PE Import Directory.
    pub parse_imports: bool,

    /// Whether to parse the PE resources tree.
    pub parse_rsrc: bool,

    /// Whether to parse PE relocations.
    pub parse_reloc: bool,

    /// Whether to parse in-depth exception metadata.
    ///
    /// This option is disabled by default because it can introduce significant
    /// parsing overhead.
    pub parse_exceptions: bool,

    /// Whether to parse nested ARM64X binaries.
    ///
    /// This option is disabled by default because it can introduce significant
    /// parsing overhead.
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

    /// Configuration that enables all optional parsing features.
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
