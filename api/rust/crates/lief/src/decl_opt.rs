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
    /// If true, the output will use C++ features (e.g. `bool` keyword)
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

    /// Emit a function body listing its local / stack variables
    pub include_locals: bool,

    /// Resolve type aliases (sugar).
    ///
    /// If true, typedef and type aliases are replaced by their underlying
    /// canonical types (e.g., `uint32_t` might become `unsigned int`).
    pub desugar: bool,

    /// Show the relative offset of each field/attribute in structures.
    ///
    /// If true, every member of a structure is prefixed with its byte offset (e.g. `/* 0x04 */`).
    pub show_field_offsets: bool,
}

impl Default for DeclOpt {
    fn default() -> DeclOpt {
        DeclOpt {
            indentation: 2,
            is_cpp: false,
            show_extended_annotations: true,
            include_types: false,
            include_locals: false,
            desugar: true,
            show_field_offsets: false,
        }
    }
}

impl DeclOpt {
    #[doc(hidden)]
    pub fn to_ffi(&self) -> cxx::UniquePtr<ffi::LIEF_DeclOpt> {
        let mut ptr = ffi::LIEF_DeclOpt::create();
        ptr.pin_mut().set_indentation(self.indentation);
        ptr.pin_mut().set_is_cpp(self.is_cpp);
        ptr.pin_mut()
            .set_show_extended_annotations(self.show_extended_annotations);
        ptr.pin_mut().set_include_types(self.include_types);
        ptr.pin_mut().set_include_locals(self.include_locals);
        ptr.pin_mut().set_desugar(self.desugar);
        ptr.pin_mut()
            .set_show_field_offsets(self.show_field_offsets);
        ptr
    }
}
