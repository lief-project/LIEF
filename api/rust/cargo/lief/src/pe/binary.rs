use lief_ffi as ffi;

use num_traits::{cast, Num};
use std::mem::size_of;
use std::pin::Pin;
use std::path::Path;

use super::builder::Config;
use super::parser_config::Config as ParserConfig;
use super::data_directory::{DataDirectories, DataDirectory};
use super::debug::{self, Entries, DebugEntry};
use super::delay_import::{DelayImport, DelayImports};
use super::export::Export;
use super::import::{Import, Imports};
use super::load_configuration::LoadConfiguration;
use super::relocation::Relocations;
use super::resources::{Manager as ResourcesManager, NodeBase};
use super::resources::Node as ResourceNode;
use super::rich_header::RichHeader;
use super::section::{Section, Sections};
use super::signature::Signatures;
use super::tls::TLS;
use super::{data_directory, signature};
use super::debug::CodeViewPDB;
use super::symbol::Symbol;
use super::exception::RuntimeExceptionFunction;
use super::coff;

use crate::common::{into_optional, FromFFI, AsFFI};
use crate::declare_iterator;
use crate::generic;
use crate::to_conv_result;
use crate::to_slice;
use crate::Error;

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
    pub fn parse(path: &str) -> Option<Self> {
        let ffi = ffi::PE_Binary::parse(path);
        if ffi.is_null() {
            return None;
        }
        Some(Binary::from_ffi(ffi))
    }

    /// Parse from a string file path and with a provided configuration
    pub fn parse_with_config(path: &str, config: ParserConfig) -> Option<Self> {
        let ffi_config = config.to_ffi();
        let ffi = ffi::PE_Binary::parse_with_config(path, &ffi_config);
        if ffi.is_null() {
            return None;
        }
        Some(Binary::from_ffi(ffi))
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

    /// Return the root of the PE's resource tree
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
    pub fn verify_signature(
        &self,
        checks: signature::VerificationChecks,
    ) -> signature::VerificationFlags {
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
    pub fn verify_with_signature(
        &self,
        sig: &signature::Signature,
        checks: signature::VerificationChecks,
    ) -> signature::VerificationFlags {
        signature::VerificationFlags::from(
            self.ptr.verify_with_signature(sig.into(), checks.into()),
        )
    }

    /// Find an import by its DLL name (case insensitive)
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

    pub fn functions(&self) -> generic::Functions {
        generic::Functions::new(self.ptr.functions())
    }

    /// Return the data directory associated with the export table
    pub fn export_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.export_dir())
    }

    /// Return the data directory associated with the import table
    pub fn import_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.import_dir())
    }

    /// Return the data directory associated with the resources tree
    pub fn rsrc_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.rsrc_dir())
    }

    /// Return the data directory associated with the exceptions
    pub fn exceptions_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.exceptions_dir())
    }

    /// Return the data directory associated with the certificate table
    /// (authenticode)
    pub fn cert_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.cert_dir())
    }

    /// Return the data directory associated with the relocation table
    pub fn relocation_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.relocation_dir())
    }

    /// Return the data directory associated with the debug table
    pub fn debug_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.debug_dir())
    }

    /// Return the data directory associated with TLS
    pub fn tls_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.tls_dir())
    }

    /// Return the data directory associated with the load config
    pub fn load_config_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.load_config_dir())
    }

    /// Return the data directory associated with the IAT
    pub fn iat_dir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.iat_dir())
    }

    /// Return the data directory associated with delayed imports
    pub fn export_delay_dirdir(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.delay_dir())
    }

    /// Get the integer value at the given virtual address
    pub fn get_int_from_virtual_address<T>(&self, addr: u64) -> Result<T, Error>
    where
        T: Num + cast::FromPrimitive + cast::ToPrimitive,
    {
        // Can't be in the generic trait because of:
        //   > for a trait to be "object safe" it needs to allow building a vtable to allow the call
        //   > to be resolvable dynamically; for more information visit
        //   > https://doc.rust-lang.org/reference/items/traits.html#object-safety
        if size_of::<T>() == size_of::<u8>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u8,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u8(value).expect(format!("Can't cast value: {}", value).as_str())
                },
                addr
            );
        }

        if size_of::<T>() == size_of::<u16>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u16,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u16(value).expect(format!("Can't cast value: {}", value).as_str())
                },
                addr
            );
        }

        if size_of::<T>() == size_of::<u32>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u32,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u32(value).expect(format!("Can't cast value: {}", value).as_str())
                },
                addr
            );
        }

        if size_of::<T>() == size_of::<u64>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u64,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u64(value).expect(format!("Can't cast value: {}", value).as_str())
                },
                addr
            );
        }

        Err(Error::NotSupported)
    }

    /// Add an imported library (i.e. `DLL`) to the binary
    pub fn add_import<'a>(&'a mut self, name: &str) -> Import<'a> {
        Import::from_ffi(self.ptr.pin_mut().add_import(name))
    }

    /// Remove the imported library with the given `name`
    pub fn remove_import(&mut self, name: &str) {
        self.ptr.pin_mut().remove_import(name);
    }

    /// Remove all libraries in the binary
    pub fn remove_all_imports(&mut self) {
        self.ptr.pin_mut().remove_all_imports();
    }

    /// Remove the TLS from the binary
    pub fn remove_tls(&mut self) {
        self.ptr.pin_mut().remove_tls();
    }

    /// Set or change the TLS information
    pub fn set_tls(&mut self, tls: &TLS) {
        self.ptr.pin_mut().set_tls(tls.as_ffi());
    }

    /// Change or set the resources tree to given node
    pub fn set_resources(&mut self, node: &dyn NodeBase) {
        self.ptr.pin_mut().set_resources(node.get_base());
    }

    /// Add a new debug entry
    pub fn add_debug_info<'a>(&'a mut self, entry: &dyn DebugEntry) -> Option<Entries<'a>> {
        into_optional(self.ptr.pin_mut().add_debug_info(entry.get_base()))
    }

    /// Remove a specific debug entry
    pub fn remove_debug<'a>(&'a mut self, entry: &dyn DebugEntry) -> bool {
        self.ptr.pin_mut().remove_debug(entry.get_base())
    }

    /// Remove all debug info
    pub fn clear_debug<'a>(&'a mut self) -> bool {
        self.ptr.pin_mut().clear_debug()
    }

    /// Return the [`CodeViewPDB`] object if present
    pub fn codeview_pdb(&self) -> Option<CodeViewPDB> {
        into_optional(self.ptr.codeview_pdb())
    }

    /// Write back the current PE binary into the file specified in parameter
    pub fn write(&mut self, output: &Path) {
        self.ptr.as_mut().unwrap().write(output.to_str().unwrap());
    }

    /// Write back the current PE binary into the file specified in parameter with the
    /// configuration provided in the second parameter.
    pub fn write_with_config(&mut self, output: &Path, config: Config) {
        let ffi_config = config.to_ffi();
        self.ptr.as_mut().unwrap().write_with_config(output.to_str().unwrap(),
            &ffi_config.as_ref().unwrap());
    }

    /// Iterator over the strings located in the COFF string table
    pub fn coff_string_table(&self) -> COFFStrings {
        COFFStrings::new(self.ptr.coff_string_table())
    }

    /// Return an iterator over the binary (COFF) symbols (if any).
    pub fn symbols(&self) -> Symbols {
        Symbols::new(self.ptr.symbols())
    }

    /// Try to find the COFF string at the given offset in the COFF string table.
    ///
    /// <div class="warning">
    /// This offset must include the first 4 bytes holding the size of the table.
    /// Hence, the first string starts a the offset 4.
    /// </div>
    pub fn find_coff_string_at(&self, offset: u32) -> Option<coff::String> {
        into_optional(self.ptr.find_coff_string_at(offset))
    }

    /// Iterator over the exception (`_RUNTIME_FUNCTION`) functions
    ///
    /// This function requires that the option [`ParserConfig::parse_exceptions`] was turned on
    /// (default is `false`) when parsing the binary.
    pub fn exceptions(&self) -> Exceptions {
        Exceptions::new(self.ptr.exceptions())
    }

    /// Try to find the exception info at the given RVA
    ///
    /// This function requires that the option [`ParserConfig::parse_exceptions`] was turned on
    /// (default is `false`) when parsing the binary.
    pub fn find_exception_at(&self, rva: u32) -> Option<RuntimeExceptionFunction> {
        into_optional(self.ptr.find_exception_at(rva))
    }

    /// True if this binary is compiled in ARM64EC mode (emulation compatible)
    pub fn is_arm64ec(&self) -> bool {
        self.ptr.is_arm64ec()
    }

    /// True if this binary is compiled in ARM64X mode (contains both ARM64 and ARM64EC).
    pub fn is_arm64x(&self) -> bool {
        self.ptr.is_arm64x()
    }

    /// If the current binary contains dynamic relocations
    /// (e.g. LIEF::PE::DynamicFixupARM64X), this function returns the
    /// **relocated** view of the current PE.
    ///
    /// This can be used to get the alternative PE binary, targeting a different
    /// architectures.
    ///
    /// <div class="warning">
    /// This function is <b>moving</b> and taking the ownership of the nested
    /// PE binary. This means that subsequent calls to this function will return None.
    /// </div>
    ///
    /// This function requires that the option [`ParserConfig::parse_arm64x_binary`] was turned on
    /// (default is `false`) when parsing the binary.
    pub fn nested_pe_binary(&self) -> Option<Binary> {
        into_optional(self.ptr.nested_pe_binary())
    }

    /// Set or change the export table
    pub fn set_export(&mut self, export: &Export) {
        self.ptr.pin_mut().set_export(export.as_ffi());
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

    fn as_pin_mut_generic(&mut self) -> Pin<&mut ffi::AbstractBinary> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref()
                    as *const ffi::AbstractBinary
                    as *mut ffi::AbstractBinary).as_mut().unwrap()
            })
        }
    }
}

declare_iterator!(
    DebugEntries,
    debug::Entries<'a>,
    ffi::PE_Debug,
    ffi::PE_Binary,
    ffi::PE_Binary_it_debug
);


declare_iterator!(
    COFFStrings,
    coff::String<'a>,
    ffi::PE_COFFString,
    ffi::PE_Binary,
    ffi::PE_Binary_it_strings_table
);

declare_iterator!(
    Symbols,
    Symbol<'a>,
    ffi::PE_Symbol,
    ffi::PE_Binary,
    ffi::PE_Binary_it_symbols
);

declare_iterator!(
    Exceptions,
    RuntimeExceptionFunction<'a>,
    ffi::PE_ExceptionInfo,
    ffi::PE_Binary,
    ffi::PE_Binary_it_exceptions
);
