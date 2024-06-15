use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;
use crate::to_slice;

use std::marker::PhantomData;


/// Structure that represents the `LC_SYMTAB` command
pub struct SymbolCommand<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_SymbolCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl SymbolCommand<'_> {
    /// Offset from the start of the file to the n_list associated with the command
    pub fn symbol_offset(&self) -> u32 {
        self.ptr.symbol_offset()
    }

    /// Number of symbols registered
    pub fn numberof_symbols(&self) -> u32 {
        self.ptr.numberof_symbols()
    }

    /// Offset from the start of the file to the string table
    pub fn strings_offset(&self) -> u32 {
        self.ptr.strings_offset()
    }

    /// Size of the size string table
    pub fn strings_size(&self) -> u32 {
        self.ptr.strings_size()
    }

    pub fn original_str_size(&self) -> u32 {
        self.ptr.original_str_size()
    }

    pub fn original_nb_symbols(&self) -> u32 {
        self.ptr.original_nb_symbols()
    }

    pub fn symbol_table(&self) -> &[u8] {
        to_slice!(self.ptr.symbol_table());
    }

    pub fn string_table(&self) -> &[u8] {
        to_slice!(self.ptr.string_table());
    }
}

impl std::fmt::Debug for SymbolCommand<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("SymbolCommand")
            .field("base", &base)
            .field("symbol_offset", &self.symbol_offset())
            .field("numberof_symbols", &self.numberof_symbols())
            .field("strings_offset", &self.strings_offset())
            .field("strings_size", &self.strings_size())
            .finish()
    }
}

impl FromFFI<ffi::MachO_SymbolCommand> for SymbolCommand<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_SymbolCommand>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for SymbolCommand<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

