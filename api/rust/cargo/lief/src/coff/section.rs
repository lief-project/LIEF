//! COFF section module

use std::marker::PhantomData;
use crate::common::into_optional;
use crate::common::FromFFI;
use crate::coff;
use crate::generic;
use crate::pe;
use super::Relocation;
use super::Symbol;
use crate::declare_iterator;

use lief_ffi as ffi;

pub struct Section<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_Section>,
    _owner: PhantomData<&'a ffi::COFF_Binary>,
}

impl FromFFI<ffi::COFF_Section> for Section<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_Section>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Section<'_> {
    /// Return the size of the data in the section.
    pub fn sizeof_raw_data(&self) -> u32 {
        self.ptr.sizeof_raw_data()
    }

    /// Return the size of the data when mapped in memory (should be 0)
    pub fn virtual_size(&self) -> u32 {
        self.ptr.virtual_size()
    }

    /// Offset to the section's content
    pub fn pointerto_raw_data(&self) -> u32 {
        self.ptr.pointerto_raw_data()
    }

    /// Offset to the relocation table
    pub fn pointerto_relocation(&self) -> u32 {
        self.ptr.pointerto_relocation()
    }

    /// The file pointer to the beginning of line-number entries for the section.
    ///
    /// This is set to zero if there are no COFF line numbers.
    /// This value should be zero for an image because COFF debugging information
    /// is deprecated and modern debug information relies on the PDB files.
    pub fn pointerto_line_numbers(&self) -> u32 {
        self.ptr.pointerto_line_numbers()
    }

    /// Number of relocations.
    ///
    /// <div class="warning">
    /// If the number of relocations is greater than 0xFFFF (maximum value for 16-bits integer),
    /// then the number of relocations is stored in the virtual address attribute.
    /// </div>
    pub fn numberof_relocations(&self) -> u16 {
        self.ptr.numberof_relocations()
    }

    /// Number of line number entries (if any).
    pub fn numberof_line_numbers(&self) -> u16 {
        self.ptr.numberof_line_numbers()
    }

    /// Characteristics of the section: it provides information about
    /// the permissions of the section when mapped. It can also provide
    /// information about the *purpose* of the section (contain code, BSS-like, ...)
    pub fn characteristics(&self) -> pe::section::Characteristics {
        pe::section::Characteristics::from(self.ptr.characteristics())
    }

    /// True if the section can be discarded as needed.
    ///
    /// This is typically the case for debug-related sections
    pub fn is_discardable(&self) -> bool {
        self.ptr.is_discardable()
    }

    /// Whether there is a large number of relocations whose number need to be stored in the
    /// virtual address attribute
    pub fn has_extended_relocations(&self) -> bool {
        self.ptr.has_extended_relocations()
    }

    /// Iterator over the relocations associated with this section
    pub fn relocations(&self) -> Relocations<'_> {
        Relocations::new(self.ptr.relocations())
    }

    /// Iterator over the symbols associated with this section
    pub fn symbols(&self) -> Symbols<'_> {
        Symbols::new(self.ptr.symbols())
    }

    /// Return comdat information (only if the section has the
    /// [`crate::pe::section::Characteristics::LNK_COMDAT`] characteristic)
    pub fn comdat_info(&self) -> Option<ComdatInfo<'_>> {
        into_optional(self.ptr.comdat_info())
    }

    /// Return the COFF string associated with the section's name (or a None)
    ///
    /// This coff string is usually present for long section names whose length
    /// does not fit in the 8 bytes allocated by the COFF format.
    pub fn coff_string(&self) -> Option<coff::String<'_>> {
        into_optional(self.ptr.coff_string())
    }
}

impl generic::Section for Section<'_> {
    fn as_generic(&self) -> &ffi::AbstractSection {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Section<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Section;
        f.debug_struct("Section")
            .field("base", &base)
            .field("sizeof_raw_data", &self.sizeof_raw_data())
            .field("virtual_size", &self.virtual_size())
            .field("pointerto_raw_data", &self.pointerto_raw_data())
            .field("pointerto_relocation", &self.pointerto_relocation())
            .field("pointerto_line_numbers", &self.pointerto_line_numbers())
            .field("numberof_relocations", &self.numberof_relocations())
            .field("numberof_line_numbers", &self.numberof_line_numbers())
            .field("characteristics", &self.characteristics())
            .finish()
    }
}

impl std::fmt::Display for Section<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

/// This structure wraps comdat information which is composed of the symbol
/// associated with the comdat section and its selection flag
pub struct ComdatInfo<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_Section_ComdataInfo>,
    _owner: PhantomData<&'a ffi::COFF_Binary>,
}

impl ComdatInfo<'_> {
    pub fn symbol(&self) -> Option<Symbol<'_>> {
        into_optional(self.ptr.symbol())
    }

    pub fn kind(&self) -> coff::symbol::ComdatSelection {
        coff::symbol::ComdatSelection::from(self.ptr.kind())
    }
}

impl FromFFI<ffi::COFF_Section_ComdataInfo> for ComdatInfo<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_Section_ComdataInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for ComdatInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComdatInfo")
            .field("symbol", &self.symbol())
            .field("kind", &self.kind())
            .finish()
    }
}


declare_iterator!(
    Relocations,
    Relocation<'a>,
    ffi::COFF_Relocation,
    ffi::COFF_Section,
    ffi::COFF_Section_it_relocations
);


declare_iterator!(
    Symbols,
    Symbol<'a>,
    ffi::COFF_Symbol,
    ffi::COFF_Section,
    ffi::COFF_Section_it_symbols
);
