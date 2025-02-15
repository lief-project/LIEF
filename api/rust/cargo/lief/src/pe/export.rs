//! PE export module

use lief_ffi as ffi;

use crate::common::into_optional;
use crate::common::{FromFFI, AsFFI};
use crate::declare_iterator;
use crate::generic;

use std::marker::PhantomData;

pub struct Export<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Export>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl Export<'_> {
    /// Create a new Export object
    pub fn new() -> Export<'static> {
        Export::from_ffi(ffi::PE_Export::create())
    }

    /// According to the PE specifications this value is reserved and should be set to 0
    pub fn export_flags(&self) -> u32 {
        self.ptr.export_flags()
    }

    /// The time and date that the export data was created
    pub fn timestamp(&self) -> u32 {
        self.ptr.timestamp()
    }

    /// The major version number (can be user-defined)
    pub fn major_version(&self) -> u16 {
        self.ptr.major_version()
    }

    /// The minor version number (can be user-defined)
    pub fn minor_version(&self) -> u16 {
        self.ptr.minor_version()
    }

    /// The starting number for the exports. Usually this value is set to 1
    pub fn ordinal_base(&self) -> u32 {
        self.ptr.ordinal_base()
    }

    /// The name of the library exported (e.g. `KERNEL32.dll`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Iterator over the different [`Entry`] exported by this table
    pub fn entries(&self) -> ExportEntries {
        ExportEntries::new(self.ptr.entries())
    }

    /// Address of the ASCII DLL's name (RVA)
    pub fn name_rva(&self) -> u32 {
        self.ptr.name_rva()
    }

    /// RVA to the list of exported names
    pub fn names_addr_table_rva(&self) -> u32 {
        self.ptr.names_addr_table_rva()
    }

    /// Number of exports by name
    pub fn names_addr_table_cnt(&self) -> u32 {
        self.ptr.names_addr_table_cnt()
    }

    /// RVA of the export address table
    pub fn export_addr_table_rva(&self) -> u32 {
        self.ptr.export_addr_table_rva()
    }

    /// Number of entries in the export address table
    pub fn export_addr_table_cnt(&self) -> u32 {
        self.ptr.export_addr_table_cnt()
    }

    /// RVA to the list of exported ordinals
    pub fn ord_addr_table_rva(&self) -> u32 {
        self.ptr.ord_addr_table_rva()
    }

    /// Change or set the export flags
    pub fn set_export_flags(&mut self, flags: u32) -> &mut Self {
        self.ptr.pin_mut().set_export_flags(flags);
        self
    }

    /// Change or set the timestamp
    pub fn set_timestamp(&mut self, timestamp: u32) -> &mut Self {
        self.ptr.pin_mut().set_export_flags(timestamp);
        self
    }

    /// Change or set the major version of the DLL
    pub fn set_major_version(&mut self, version: u32) -> &mut Self {
        self.ptr.pin_mut().set_major_version(version);
        self
    }

    /// Change or set the minor version of the DLL
    pub fn set_minor_version(&mut self, version: u32) -> &mut Self {
        self.ptr.pin_mut().set_minor_version(version);
        self
    }

    /// Change or set the name of the DLL
    pub fn set_name(&mut self, name: &str) -> &mut Self {
        self.ptr.pin_mut().set_name(name);
        self
    }

    /// Find the export entry with the given name
    pub fn entry_by_name(&self, name: &str) -> Option<Entry> {
        into_optional(self.ptr.entry_by_name(name))
    }

    /// Find the export entry with the given ordinal number
    pub fn entry_by_ordinal(&self, ordinal: u32) -> Option<Entry> {
        into_optional(self.ptr.entry_by_ordinal(ordinal))
    }

    /// Find the export entry at the provided RVA
    pub fn entry_at_rva(&self, rva: u32) -> Option<Entry> {
        into_optional(self.ptr.entry_at_rva(rva))
    }

    /// Add the given export and return the newly created and added export
    pub fn add_entry(&mut self, entry: &Entry) -> Entry {
        Entry::from_ffi(self.ptr.pin_mut().add_entry(entry.ptr.as_ref().unwrap()))
    }

    /// Add a new export entry given its name and its RVA
    pub fn add_entry_by_name(&mut self, name: &str, rva: u32) -> Entry {
        Entry::from_ffi(self.ptr.pin_mut().add_entry_by_name(name, rva))
    }

    /// Remove the given export entry
    pub fn remove_entry(&mut self, entry: Entry) -> bool {
        self.ptr.pin_mut().remove_entry(entry.ptr)
    }

    /// Remove the export entry with the given RVA
    pub fn remove_entry_at(&mut self, rva: u32) -> bool {
        self.ptr.pin_mut().remove_entry_at(rva)
    }

    /// Remove the export entry with the given RVA
    pub fn remove_entry_by_name(&mut self, name: &str) -> bool {
        self.ptr.pin_mut().remove_entry_by_name(name)
    }

}

impl std::fmt::Debug for Export<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Export")
            .field("export_flags", &self.export_flags())
            .field("timestamp", &self.timestamp())
            .field("major_version", &self.major_version())
            .field("minor_version", &self.minor_version())
            .field("ordinal_base", &self.ordinal_base())
            .field("name", &self.name())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_Export> for Export<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Export>) -> Self {
        Export {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> AsFFI<ffi::PE_Export> for Export<'a> {
    fn as_ffi(&self) -> &ffi::PE_Export {
        self.ptr.as_ref().unwrap()
    }

    fn as_mut_ffi(&mut self) -> std::pin::Pin<&mut ffi::PE_Export> {
        self.ptr.pin_mut()
    }
}

/// Structure which represents an entry in the export table.
///
/// It implements the [`generic::Symbol`] trait that exposes [`generic::Symbol::name`] and
/// [`generic::Symbol::value`].
pub struct Entry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ExportEntry>,
    _owner: PhantomData<&'a ffi::PE_Export>,
}

impl Entry<'_> {
    /// Ordinal value associated with this exported entry.
    ///
    /// This value is computed as the index of this entry in the address table
    /// plus the ordinal base ([`Export::ordinal_base`])
    pub fn ordinal(&self) -> u16 {
        self.ptr.ordinal()
    }

    /// Address of the current exported function in the DLL.
    ///
    /// If this entry is **external** to the DLL then it returns 0
    /// and the external address is returned by [`Entry::function_rva`]
    pub fn address(&self) -> u32 {
        self.ptr.address()
    }

    pub fn function_rva(&self) -> u32 {
        self.ptr.function_rva()
    }

    pub fn is_extern(&self) -> bool {
        self.ptr.is_extern()
    }

    pub fn is_forwarded(&self) -> bool {
        self.ptr.is_forwarded()
    }

    /// Demangled representation of the symbol or an empty string if it can't
    /// be demangled
    pub fn demangled_name(&self) -> String {
        self.ptr.demangled_name().to_string()
    }

    pub fn forward_info(&self) -> Option<ForwardInfo> {
        if !self.ptr.is_forwarded() {
            return None;
        }
        Some(ForwardInfo::with_values(self.ptr.fwd_library().to_string(), self.ptr.fwd_function().to_string()))
    }

    pub fn set_ordinal(&mut self, ordinal: u16) -> &mut Self {
        self.ptr.pin_mut().set_ordinal(ordinal);
        self
    }

    pub fn set_address(&mut self, address: u32) -> &mut Self {
        self.ptr.pin_mut().set_address(address);
        self
    }
}

impl generic::Symbol for Entry<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Entry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("ExportEntry")
            .field("base", &base)
            .field("ordinal", &self.ordinal())
            .field("address", &self.address())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ExportEntry> for Entry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ExportEntry>) -> Self {
        Entry {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub struct ForwardInfo {
    pub library: String,
    pub function: String,
}

impl ForwardInfo {
    pub fn with_values(library: String, function: String) -> Self {
        Self {
            library, function
        }
    }
}

declare_iterator!(
    ExportEntries,
    Entry<'a>,
    ffi::PE_ExportEntry,
    ffi::PE_Export,
    ffi::PE_Export_it_entries
);
