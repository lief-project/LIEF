use lief_ffi as ffi;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Configuration options for generated code from debug info.
///
/// This structure configures how the debug information (DWARF/PDB) translated
/// into an AST is generated.
pub struct DeclOpt {
    pub indentation: u32,

    /// Prefer C++ syntax over C syntax.
    ///
    /// If true, the output will use C++ features (e.g., `bool` keyword)
    pub is_cpp: bool,

    /// Enable extended comments and annotations.
    ///
    /// If true, the generated code will include comments containing low-level
    /// details such as memory addresses, offsets, type sizes, and original
    /// source locations.
    pub show_extended_annotations: bool,

    /// Include full type definitions.
    ///
    /// If true, the output will contain the full definition of types (structs,
    /// enums, unions).
    pub include_types: bool,

    /// Resolve type aliases (sugar).
    ///
    /// If true, `typedef`s and type aliases are replaced by their underlying
    /// canonical types (e.g., `uint32_t` might become `unsigned int`).
    pub desugar: bool,

}

impl Default for DeclOpt {
    fn default() -> DeclOpt {
        DeclOpt {
            indentation: 2,
            is_cpp: false,
            show_extended_annotations: true,
            include_types: false,
            desugar: true,
        }
    }
}

impl DeclOpt {
    #[doc(hidden)]
    pub fn to_ffi(&self) -> cxx::UniquePtr<ffi::LIEF_DeclOpt> {
        let mut ptr = ffi::LIEF_DeclOpt::create();
        ptr.pin_mut().set_indentation(self.indentation);
        ptr
    }
}
