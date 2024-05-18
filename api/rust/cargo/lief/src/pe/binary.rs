use lief_ffi as ffi;

use super::data_directory::DataDirectories;
use super::debug;
use super::delay_import::DelayImports;
use super::export::Export;
use super::import::Imports;
use super::load_configuration::LoadConfiguration;
use super::relocation::Relocations;
use super::resources::Manager as ResourcesManager;
use super::resources::Node as ResourceNode;
use super::rich_header::RichHeader;
use super::section::Sections;
use super::signature::Signatures;
use super::tls::TLS;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::generic;
use crate::to_slice;

use super::Algorithms;
use super::{DosHeader, Header, OptionalHeader};

pub struct Binary {
    ptr: cxx::UniquePtr<ffi::PE_Binary>,
}

impl FromFFI<ffi::PE_Binary> for Binary {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Binary>) -> Self {
        Self { ptr }
    }
}

impl Binary {
    pub fn parse(path: &str) -> Self {
        let bin = ffi::PE_Binary::parse(path);
        Self { ptr: bin }
    }

    pub fn dos_header(&self) -> DosHeader {
        DosHeader::from_ffi(self.ptr.dos_header())
    }

    pub fn optional_header(&self) -> OptionalHeader {
        OptionalHeader::from_ffi(self.ptr.optional_header())
    }

    pub fn compute_checksum(&self) -> u32 {
        self.ptr.compute_checksum()
    }

    pub fn header(&self) -> Header {
        Header::from_ffi(self.ptr.header())
    }

    pub fn tls(&self) -> Option<TLS> {
        into_optional(self.ptr.tls())
    }

    pub fn rich_header(&self) -> Option<RichHeader> {
        into_optional(self.ptr.rich_header())
    }

    pub fn export(&self) -> Option<Export> {
        into_optional(self.ptr.get_export())
    }

    pub fn resources(&self) -> Option<ResourceNode> {
        into_optional(self.ptr.resources())
    }

    pub fn resources_manager(&self) -> Option<ResourcesManager> {
        into_optional(self.ptr.resources_manager())
    }

    pub fn imports(&self) -> Imports {
        Imports::new(self.ptr.imports())
    }

    pub fn data_directories(&self) -> DataDirectories {
        DataDirectories::new(self.ptr.data_directories())
    }

    pub fn sections(&self) -> Sections {
        Sections::new(self.ptr.sections())
    }

    pub fn relocations(&self) -> Relocations {
        Relocations::new(self.ptr.relocations())
    }

    pub fn delay_imports(&self) -> DelayImports {
        DelayImports::new(self.ptr.delay_imports())
    }

    pub fn signatures(&self) -> Signatures {
        Signatures::new(self.ptr.signatures())
    }

    pub fn debug(&self) -> DebugEntries {
        DebugEntries::new(self.ptr.debug())
    }

    pub fn authentihash(&self, algo: Algorithms) -> Vec<u8> {
        Vec::from(self.ptr.authentihash(algo as u32).as_slice())
    }

    pub fn load_configuration(&self) -> Option<LoadConfiguration> {
        into_optional(self.ptr.load_configuration())
    }

    pub fn dos_stub(&self) -> &[u8] {
        to_slice!(self.ptr.dos_stub());
    }

    pub fn overlay(&self) -> &[u8] {
        to_slice!(self.ptr.overlay());
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
