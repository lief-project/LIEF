use super::Command;
use crate::common::FromFFI;
use lief_ffi as ffi;
use std::marker::PhantomData;

/// Structure that represents the `LC_DYSYMTAB` command.
///
/// This command completes the `LC_SYMTAB` to provide
/// a better granularity over the symbols layout.
pub struct DynamicSymbolCommand<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_DynamicSymbolCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl DynamicSymbolCommand<'_> {
    /// Index of the first symbol in the group of local symbols.
    pub fn idx_local_symbol(&self) -> u32 {
        self.ptr.idx_local_symbol()
    }

    /// Number of symbols in the group of local symbols.
    pub fn nb_local_symbols(&self) -> u32 {
        self.ptr.nb_local_symbols()
    }

    /// Index of the first symbol in the group of defined external symbols.
    pub fn idx_external_define_symbol(&self) -> u32 {
        self.ptr.idx_external_define_symbol()
    }

    /// Number of symbols in the group of defined external symbols.
    pub fn nb_external_define_symbols(&self) -> u32 {
        self.ptr.nb_external_define_symbols()
    }

    /// Index of the first symbol in the group of undefined external symbols.
    pub fn idx_undefined_symbol(&self) -> u32 {
        self.ptr.idx_undefined_symbol()
    }

    /// Number of symbols in the group of undefined external symbols.
    pub fn nb_undefined_symbols(&self) -> u32 {
        self.ptr.nb_undefined_symbols()
    }

    /// Byte offset from the start of the file to the table of contents data
    ///
    /// Table of content is used by legacy Mach-O loader and this field should be
    /// set to 0
    pub fn toc_offset(&self) -> u32 {
        self.ptr.toc_offset()
    }

    /// Number of entries in the table of contents.
    ///
    /// Should be set to 0 on recent Mach-O
    pub fn nb_toc(&self) -> u32 {
        self.ptr.nb_toc()
    }

    /// Byte offset from the start of the file to the module table data.
    ///
    /// This field seems unused by recent Mach-O loader and should be set to 0
    pub fn module_table_offset(&self) -> u32 {
        self.ptr.module_table_offset()
    }

    /// Number of entries in the module table.
    ///
    /// This field seems unused by recent Mach-O loader and should be set to 0
    pub fn nb_module_table(&self) -> u32 {
        self.ptr.nb_module_table()
    }

    /// Byte offset from the start of the file to the external reference table data.
    ///
    /// This field seems unused by recent Mach-O loader and should be set to 0
    pub fn external_reference_symbol_offset(&self) -> u32 {
        self.ptr.external_reference_symbol_offset()
    }

    /// Number of entries in the external reference table
    ///
    /// This field seems unused by recent Mach-O loader and should be set to 0
    pub fn nb_external_reference_symbols(&self) -> u32 {
        self.ptr.nb_external_reference_symbols()
    }

    /// Byte offset from the start of the file to the indirect symbol table data.
    ///
    /// Indirect symbol table is used by the loader to speed-up symbol resolution during
    /// the *lazy binding* process
    ///
    /// References:
    ///   * dyld-519.2.1/src/ImageLoaderMachOCompressed.cpp
    ///   * dyld-519.2.1/src/ImageLoaderMachOClassic.cpp
    pub fn indirect_symbol_offset(&self) -> u32 {
        self.ptr.indirect_symbol_offset()
    }

    /// Number of entries in the indirect symbol table.
    pub fn nb_indirect_symbols(&self) -> u32 {
        self.ptr.nb_indirect_symbols()
    }

    /// Byte offset from the start of the file to the external relocation table data.
    ///
    /// This field seems unused by recent Mach-O loader and should be set to 0
    pub fn external_relocation_offset(&self) -> u32 {
        self.ptr.external_relocation_offset()
    }


    /// Number of entries in the external relocation table.
    ///
    /// This field seems unused by recent Mach-O loader and should be set to 0
    pub fn nb_external_relocations(&self) -> u32 {
        self.ptr.nb_external_relocations()
    }

    /// Byte offset from the start of the file to the local relocation table data.
    ///
    /// This field seems unused by recent Mach-O loader and should be set to 0
    pub fn local_relocation_offset(&self) -> u32 {
        self.ptr.local_relocation_offset()
    }

    /// Number of entries in the local relocation table.
    ///
    /// This field seems unused by recent Mach-O loader and should be set to 0
    pub fn nb_local_relocations(&self) -> u32 {
        self.ptr.nb_local_relocations()
    }
}

impl std::fmt::Debug for DynamicSymbolCommand<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("DynamicSymbolCommand")
            .field("base", &base)
            .field("idx_local_symbol", &self.idx_local_symbol())
            .field("nb_local_symbols", &self.nb_local_symbols())
            .field(
                "idx_external_define_symbol",
                &self.idx_external_define_symbol(),
            )
            .field(
                "nb_external_define_symbols",
                &self.nb_external_define_symbols(),
            )
            .field("idx_undefined_symbol", &self.idx_undefined_symbol())
            .field("nb_undefined_symbols", &self.nb_undefined_symbols())
            .field("toc_offset", &self.toc_offset())
            .field("nb_toc", &self.nb_toc())
            .field("module_table_offset", &self.module_table_offset())
            .field("nb_module_table", &self.nb_module_table())
            .field(
                "external_reference_symbol_offset",
                &self.external_reference_symbol_offset(),
            )
            .field(
                "nb_external_reference_symbols",
                &self.nb_external_reference_symbols(),
            )
            .field("indirect_symbol_offset", &self.indirect_symbol_offset())
            .field("nb_indirect_symbols", &self.nb_indirect_symbols())
            .field(
                "external_relocation_offset",
                &self.external_relocation_offset(),
            )
            .field("nb_external_relocations", &self.nb_external_relocations())
            .field("local_relocation_offset", &self.local_relocation_offset())
            .field("nb_local_relocations", &self.nb_local_relocations())
            .finish()
    }
}

impl FromFFI<ffi::MachO_DynamicSymbolCommand> for DynamicSymbolCommand<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_DynamicSymbolCommand>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for DynamicSymbolCommand<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
