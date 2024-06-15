//! PE Delayed import module
use std::marker::PhantomData;

use crate::{common::FromFFI, declare_iterator, generic};
use lief_ffi as ffi;

pub struct DelayImport<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DelayImport>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl DelayImport<'_> {
    /// According to the official PE specifications, this value is reserved and should be set to 0
    pub fn attribute(&self) -> u32 {
        self.ptr.attribute()
    }

    /// Return the library's name (e.g. `kernel32.dll`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// The RVA of the module handle (in the ``.data`` section).
    /// It is used for storage by the routine that is supplied to manage delay-loading.
    pub fn handle(&self) -> u32 {
        self.ptr.handle()
    }

    /// RVA of the delay-load import address table.
    pub fn iat(&self) -> u32 {
        self.ptr.iat()
    }

    /// RVA of the delay-load import names table.
    ///
    /// The content of this table has the layout as the Import lookup table
    pub fn names_table(&self) -> u32 {
        self.ptr.names_table()
    }

    /// RVA of the **bound** delay-load import address table or 0 if the table does not exist.
    pub fn biat(&self) -> u32 {
        self.ptr.biat()
    }


    /// RVA of the **unload** delay-load import address table or 0
    /// if the table does not exist.
    ///
    /// According to the PE specifications, this table is an
    /// exact copy of the delay import address table that can be
    /// used to to restore the original IAT the case of unloading.
    pub fn uiat(&self) -> u32 {
        self.ptr.uiat()
    }

    /// The timestamp of the DLL to which this image has been bound.
    pub fn timestamp(&self) -> u32 {
        self.ptr.timestamp()
    }

    /// Iterator over the DelayImport's entries ([`DelayImportEntry`])
    pub fn entries(&self) -> Entries {
        Entries::new(self.ptr.entries())
    }
}

impl std::fmt::Debug for DelayImport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelayImport")
            .field("attribute", &self.attribute())
            .field("name", &self.name())
            .field("handle", &self.handle())
            .field("iat", &self.iat())
            .field("names_table", &self.names_table())
            .field("biat", &self.biat())
            .field("uiat", &self.uiat())
            .field("timestamp", &self.timestamp())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_DelayImport> for DelayImport<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DelayImport>) -> Self {
        DelayImport {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Structure that represents an entry (i.e. an import) in the delay import table.
///
/// It implements the [`generic::Symbol`] trait that exposes [`generic::Symbol::name`] and
/// [`generic::Symbol::value`].
///
/// The meaning of [`generic::Symbol::value`] for this PE object is the address (as an RVA) in the
/// IAT where the resolution should take place.
pub struct DelayImportEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DelayImportEntry>,
    _owner: PhantomData<&'a ffi::PE_DelayImport>,
}

impl DelayImportEntry<'_> {
    /// `True` if it is an import by ordinal
    pub fn is_ordinal(&self) -> bool {
        self.ptr.is_ordinal()
    }

    /// The ordinal value
    pub fn ordinal(&self) -> u16 {
        self.ptr.ordinal()
    }

    /// See: [`DelayImportEntry::data`]
    pub fn hint_name_rva(&self) -> u64 {
        self.ptr.hint_name_rva()
    }

    /// Index into the export table that is used to speed-up the symbol resolution
    pub fn hint(&self) -> u16 {
        self.ptr.hint()
    }

    /// Value of the current entry in the Import Address Table.
    pub fn iat_value(&self) -> u64 {
        self.ptr.iat_value()
    }

    /// Raw value
    pub fn data(&self) -> u64 {
        self.ptr.data()
    }
}

impl generic::Symbol for DelayImportEntry<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for DelayImportEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("DelayImportEntry")
            .field("base", &base)
            .field("ordinal", &self.ordinal())
            .field("hint_name_rva", &self.hint_name_rva())
            .field("hint", &self.hint())
            .field("iat_value", &self.iat_value())
            .field("data", &self.data())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_DelayImportEntry> for DelayImportEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DelayImportEntry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

declare_iterator!(
    DelayImports,
    DelayImport<'a>,
    ffi::PE_DelayImport,
    ffi::PE_Binary,
    ffi::PE_Binary_it_delay_imports
);
declare_iterator!(
    Entries,
    DelayImportEntry<'a>,
    ffi::PE_DelayImportEntry,
    ffi::PE_DelayImport,
    ffi::PE_DelayImport_it_entries
);
