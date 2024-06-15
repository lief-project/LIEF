use lief_ffi as ffi;

use super::{data_directory, signature};
use super::data_directory::{DataDirectories, DataDirectory};
use super::debug;
use super::delay_import::{DelayImports, DelayImport};
use super::export::Export;
use super::import::{Imports, Import};
use super::load_configuration::LoadConfiguration;
use super::relocation::Relocations;
use super::resources::Manager as ResourcesManager;
use super::resources::Node as ResourceNode;
use super::rich_header::RichHeader;
use super::section::{Sections, Section};
use super::signature::Signatures;
use super::tls::TLS;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::generic;
use crate::to_slice;

use super::Algorithms;
use super::{DosHeader, Header, OptionalHeader};

/// This is the main interface to read and write PE binary attributes.
///
/// Note that this structure implements the [`generic::Binary`] trait from which other generic
/// functions are exposed
///
/// ```
/// fn use_trait(pe: &Binary) {
///     let generic_binary = pe as &dyn generic::Binary;
///     println!("{}", generic_binary.entrypoint());
/// }
///
/// ```
pub struct Binary {
    ptr: cxx::UniquePtr<ffi::PE_Binary>,
}

impl FromFFI<ffi::PE_Binary> for Binary {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Binary>) -> Self {
        Self { ptr }
    }
}

impl Binary {
    /// Parse from a file path given as a string
    pub fn parse(path: &str) -> Self {
        let bin = ffi::PE_Binary::parse(path);
        Self { ptr: bin }
    }

    /// DosHeader which starts the PE files
    pub fn dos_header(&self) -> DosHeader {
        DosHeader::from_ffi(self.ptr.dos_header())
    }

    /// Header that follows the [`Binary::header`]. It is named
    /// *optional* from the COFF specfication but it is mandatory in a PE file.
    pub fn optional_header(&self) -> OptionalHeader {
        OptionalHeader::from_ffi(self.ptr.optional_header())
    }

    /// Re-compute the value of [`OptionalHeader::checksum`]
    pub fn compute_checksum(&self) -> u32 {
        self.ptr.compute_checksum()
    }

    /// Next header after the [`Binary::dos_header`]
    pub fn header(&self) -> Header {
        Header::from_ffi(self.ptr.header())
    }

    /// Return TLS information if present
    pub fn tls(&self) -> Option<TLS> {
        into_optional(self.ptr.tls())
    }

    /// Return rich header information if present.
    pub fn rich_header(&self) -> Option<RichHeader> {
        into_optional(self.ptr.rich_header())
    }

    /// Return export information
    pub fn export(&self) -> Option<Export> {
        into_optional(self.ptr.get_export())
    }

    /// Return the root of the PE's resource's tree
    pub fn resources(&self) -> Option<ResourceNode> {
        into_optional(self.ptr.resources())
    }

    /// Return a manager interface to read and manipulate the resources tree with a user friendly
    /// interface.
    pub fn resources_manager(&self) -> Option<ResourcesManager> {
        into_optional(self.ptr.resources_manager())
    }

    /// Return the imports as an **iterator** over the [`Import`] structure
    pub fn imports(&self) -> Imports {
        Imports::new(self.ptr.imports())
    }

    /// Return the data directories as an iterator over the [`DataDirectory`] structure
    pub fn data_directories(&self) -> DataDirectories {
        DataDirectories::new(self.ptr.data_directories())
    }

    /// Return the sections as an iterator over the [`Section`] structure
    pub fn sections(&self) -> Sections {
        Sections::new(self.ptr.sections())
    }

    /// Return the relocations as an iterator over the [`super::Relocation`] structure
    pub fn relocations(&self) -> Relocations {
        Relocations::new(self.ptr.relocations())
    }

    /// Return the delayed imports as an iterator over the [`DelayImport`] structure
    pub fn delay_imports(&self) -> DelayImports {
        DelayImports::new(self.ptr.delay_imports())
    }

    /// Return an iterator over the [`signature::Signature`] if the current PE is authenticode-signed.
    pub fn signatures(&self) -> Signatures {
        Signatures::new(self.ptr.signatures())
    }

    /// Return an iterator over the [`debug::Entries`] of the binary.
    pub fn debug(&self) -> DebugEntries {
        DebugEntries::new(self.ptr.debug())
    }

    /// Compute the authentihash for the current PE with the given algorithms.
    pub fn authentihash(&self, algo: Algorithms) -> Vec<u8> {
        Vec::from(self.ptr.authentihash(algo.into()).as_slice())
    }

    /// Return load configuration info if present.
    pub fn load_configuration(&self) -> Option<LoadConfiguration> {
        into_optional(self.ptr.load_configuration())
    }

    /// Return the raw data between the [`Binary::dos_header`] and the regular [`Binary::header`]
    pub fn dos_stub(&self) -> &[u8] {
        to_slice!(self.ptr.dos_stub());
    }

    /// Return the original overlay data of the file
    pub fn overlay(&self) -> &[u8] {
        to_slice!(self.ptr.overlay());
    }

    /// Return the offset computed by LIEF to identify overlay data
    pub fn overlay_offset(&self) -> u64 {
        self.ptr.overlay_offset()
    }

    /// Convert a **relative** virtual address into an offset
    pub fn rva_to_offset(&self, rva: u64) -> u64 {
        self.ptr.rva_to_offset(rva)
    }

    /// Convert an **absolute** virtual address into an offset.
    pub fn va_to_offset(&self, va: u64) -> u64 {
        self.ptr.va_to_offset(va)
    }

    /// Return the size of the current binary when loaded in memory.
    pub fn virtual_size(&self) -> u64 {
        self.ptr.virtual_size()
    }

    /// Compute the size of all the headers.
    pub fn sizeof_headers(&self) -> u64 {
        self.ptr.sizeof_headers()
    }

    /// Find a section by its offset
    pub fn section_from_offset(&self, offset: u64) -> Option<Section> {
        into_optional(self.ptr.section_from_offset(offset))
    }

    /// Find a section by its **relative** virtual address
    pub fn section_from_rva(&self, rva: u64) -> Option<Section> {
        into_optional(self.ptr.section_from_rva(rva))
    }

    /// Find a section by its name
    pub fn section_by_name(&self, name: &str) -> Option<Section> {
        into_optional(self.ptr.section_by_name(name))
    }

    /// Find the data directory with the given type
    pub fn data_directory_by_type(&self, dir_type: data_directory::Type) -> Option<DataDirectory> {
        into_optional(self.ptr.data_directory_by_type(dir_type.into()))
    }

    /// Verify the binary against the embedded signature(s) (if any)
    ///
    /// First, it checks that the embedded signatures are correct (c.f. [`signature::Signature::check`])
    /// and then, it checks that the authentihash matches [`crate::pe::signature::content_info::ContentInfo::digest`]
    pub fn verify_signature(&self, checks: signature::VerificationChecks) -> signature::VerificationFlags {
        signature::VerificationFlags::from(self.ptr.verify_signature(checks.into()))
    }

    /// Verify the binary with the [`signature::Signature`] object provided in the first parameter.
    /// It can be used to verify a detached signature:
    ///
    /// ```
    /// if let Some(sig) = Signature::from_file(path_str.unwrap()) {
    ///     pe.verify_signature(&sig, signature::VerificationChecks::DEFAULT);
    /// }
    /// ```
    pub fn verify_with_signature(&self, sig: &signature::Signature, checks: signature::VerificationChecks) -> signature::VerificationFlags {
        signature::VerificationFlags::from(self.ptr.verify_with_signature(sig.into(), checks.into()))
    }

    /// Find an import by its DLL name
    pub fn import_by_name(&self, name: &str) -> Option<Import> {
        into_optional(self.ptr.import_by_name(name))
    }

    /// Find a delayed import by its name
    pub fn delay_import_by_name(&self, name: &str) -> Option<DelayImport> {
        into_optional(self.ptr.delay_import_by_name(name))
    }

    /// Return the sized content from the virtual address
    pub fn content_from_virtual_address(&self, address: u64, size: u64) -> &[u8] {
        to_slice!(self.ptr.get_content_from_virtual_address(address, size));
    }
}

impl std::fmt::Debug for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binary").finish()
    }
}

impl generic::Binary for Binary {
    fn as_generic(&self) -> &ffi::AbstractBinary {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(
    DebugEntries,
    debug::Entries<'a>,
    ffi::PE_Debug,
    ffi::PE_Binary,
    ffi::PE_Binary_it_debug
);
