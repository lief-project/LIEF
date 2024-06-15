//! This module represents PE's Imports

use std::marker::PhantomData;

use crate::common::into_optional;
use crate::declare_iterator;
use crate::pe::DataDirectory;
use crate::{common::FromFFI, generic};
use lief_ffi as ffi;

pub struct Import<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Import>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for Import<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Import")
            .field("name", &self.name())
            .field("forwarder_chain", &self.forwarder_chain())
            .field("timedatestamp", &self.timedatestamp())
            .field("import_address_table_rva", &self.import_address_table_rva())
            .field("import_lookup_table_rva", &self.import_lookup_table_rva())
            .field("directory", &self.directory())
            .field("iat_directory", &self.iat_directory())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_Import> for Import<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Import>) -> Self {
        Import {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Import<'_> {
    /// Iterator over the [`ImportEntry`]
    pub fn entries(&self) -> ImportEntries {
        ImportEntries::new(self.ptr.entries())
    }

    /// The index of the first forwarder reference
    pub fn forwarder_chain(&self) -> u32 {
        self.ptr.forwarder_chain()
    }

    /// The stamp that is set to zero until the image is bound.
    /// After the image is bound, this field is set to the time/data stamp of the DLL
    pub fn timedatestamp(&self) -> u32 {
        self.ptr.timedatestamp()
    }

    /// The RVA of the import address table (`IAT`). The content of this table is
    /// **identical** to the content of the Import Lookup Table (`ILT`) until the image is bound.
    ///
    /// <div class="warning">This address could change when re-building the binary</div>
    pub fn import_address_table_rva(&self) -> u32 {
        self.ptr.import_address_table_rva()
    }

    /// Return the relative virtual address of the import lookup table
    ///
    /// <div class="warning">This address could change when re-building the binary</div>
    pub fn import_lookup_table_rva(&self) -> u32 {
        self.ptr.import_lookup_table_rva()
    }

    /// Return the library's name (e.g. `kernel32.dll`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Return the [`DataDirectory`] associated with this import.
    pub fn directory(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.directory())
    }

    /// Return the [`DataDirectory`] associated with the IAT (import address table).
    pub fn iat_directory(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.iat_directory())
    }

    /// Try to find an [`ImportEntry`] by its name
    pub fn entry_by_name(&self, name: &str) -> Option<ImportEntry> {
        into_optional(self.ptr.entry_by_name(name))
    }

}

/// Structure that represents an entry (i.e. an import) in the regular import table.
///
/// It implements the [`generic::Symbol`] trait that exposes [`generic::Symbol::name`] and
/// [`generic::Symbol::value`].
pub struct ImportEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ImportEntry>,
    _owner: PhantomData<&'a ffi::PE_Import>,
}

impl ImportEntry<'_> {
    /// `True` if it is an import by ordinal
    pub fn is_ordinal(&self) -> bool {
        self.ptr.is_ordinal()
    }

    /// The ordinal value
    pub fn ordinal(&self) -> u16 {
        self.ptr.ordinal()
    }
    pub fn hint_name_rva(&self) -> u64 {
        self.ptr.hint_name_rva()
    }

    /// Index into the export table that is used to speed-up the resolution
    pub fn hint(&self) -> u16 {
        self.ptr.hint()
    }

    /// Value of the current entry in the Import Address Table.
    /// It should match the lookup table value
    pub fn iat_value(&self) -> u64 {
        self.ptr.iat_value()
    }

    /// Raw value
    pub fn data(&self) -> u64 {
        self.ptr.data()
    }

    /// **Original** address of the entry in the Import Address Table
    pub fn iat_address(&self) -> u64 {
        self.ptr.iat_address()
    }
}

impl<'a> FromFFI<ffi::PE_ImportEntry> for ImportEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ImportEntry>) -> Self {
        ImportEntry {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl generic::Symbol for ImportEntry<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for ImportEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("ImportEntry")
            .field("base", &base)
            .field("ordinal", &self.ordinal())
            .field("hint_name_rva", &self.hint_name_rva())
            .field("hint", &self.hint())
            .field("iat_value", &self.iat_value())
            .field("data", &self.data())
            .field("iat_address", &self.iat_address())
            .finish()
    }
}

declare_iterator!(
    ImportEntries,
    ImportEntry<'a>,
    ffi::PE_ImportEntry,
    ffi::PE_Import,
    ffi::PE_Import_it_entries
);
declare_iterator!(
    Imports,
    Import<'a>,
    ffi::PE_Import,
    ffi::PE_Binary,
    ffi::PE_Binary_it_imports
);
