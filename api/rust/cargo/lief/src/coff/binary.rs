use lief_ffi as ffi;
use crate::common::FromFFI;

use crate::common::into_optional;
use crate::declare_iterator;
use super::{Relocation, Symbol, Section, Header, String};

pub struct Binary {
    ptr: cxx::UniquePtr<ffi::COFF_Binary>,
}

impl FromFFI<ffi::COFF_Binary> for Binary {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_Binary>) -> Self {
        Self { ptr }
    }
}

impl Binary {
    /// Parse from a file path given as a string
    pub fn parse(path: &str) -> Option<Self> {
        let ffi = ffi::COFF_Binary::parse(path);
        if ffi.is_null() {
            return None;
        }
        Some(Binary::from_ffi(ffi))
    }

    /// The COFF header
    pub fn header(&self) -> Header {
        Header::from_ffi(self.ptr.header())
    }

    /// Iterator over the different sections located in this COFF binary
    pub fn sections(&self) -> Sections {
        Sections::new(self.ptr.sections())
    }

    /// Iterator over **all** the relocations used by this COFF binary
    pub fn relocations(&self) -> Relocations {
        Relocations::new(self.ptr.relocations())
    }

    /// Iterator over the COFF's symbols
    pub fn symbols(&self) -> Symbols {
        Symbols::new(self.ptr.symbols())
    }

    /// Iterator over the COFF's strings
    pub fn string_table(&self) -> Strings {
        Strings::new(self.ptr.string_table())
    }

    /// Try to find the COFF string at the given offset in the COFF string table.
    ///
    /// <div class="warning">
    /// This offset must include the first 4 bytes holding the size of the table. Hence,
    /// the first string starts a the offset 4.
    /// </div>
    pub fn find_string(&self, offset: u32) -> Option<String> {
        into_optional(self.ptr.find_string(offset))
    }
}

impl std::fmt::Display for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

impl std::fmt::Debug for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("COFF Binary")
            .finish()
    }
}



declare_iterator!(
    Relocations,
    Relocation<'a>,
    ffi::COFF_Relocation,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_relocations
);

declare_iterator!(
    Sections,
    Section<'a>,
    ffi::COFF_Section,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_sections
);


declare_iterator!(
    Symbols,
    Symbol<'a>,
    ffi::COFF_Symbol,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_symbols
);


declare_iterator!(
    Strings,
    String<'a>,
    ffi::COFF_String,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_strings
);
