//! PE Factory module for creating PE binaries from scratch

use lief_ffi as ffi;

use crate::common::{into_optional, AsFFI, FromFFI};
use crate::pe;

/// Factory for creating PE binaries from scratch
///
/// ```
/// use lief::pe;
///
/// if let Some(mut factory) = pe::Factory::create(pe::PE_TYPE::PE32_PLUS) {
///     let section = pe::Section::new_with_name(".text");
///     factory.add_section(&section);
///     factory.set_entrypoint(0x1000);
///     if let Some(binary) = factory.get() {
///         // use binary
///     }
/// }
/// ```
pub struct Factory {
    ptr: cxx::UniquePtr<ffi::PE_Factory>,
}

impl FromFFI<ffi::PE_Factory> for Factory {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Factory>) -> Self {
        Self { ptr }
    }
}

impl Factory {
    /// Create a new factory for the given PE type (PE32 or PE32+)
    pub fn create(pe_type: pe::PE_TYPE) -> Option<Factory> {
        into_optional(ffi::PE_Factory::create(pe_type.into()))
    }

    /// Add a section to the PE being built
    pub fn add_section(&mut self, section: &pe::Section) {
        self.ptr.pin_mut().add_section(section.as_ffi());
    }

    /// Set the target architecture
    pub fn set_arch(&mut self, arch: pe::headers::MachineType) {
        self.ptr.pin_mut().set_arch(arch.into());
    }

    /// Set the entry point address
    pub fn set_entrypoint(&mut self, ep: u64) {
        self.ptr.pin_mut().set_entrypoint(ep);
    }

    /// Build and return the PE binary
    pub fn get(&mut self) -> Option<pe::Binary> {
        into_optional(self.ptr.pin_mut().get())
    }

    /// Whether the factory is creating a 32-bit PE
    pub fn is_32bit(&self) -> bool {
        self.ptr.is_32bit()
    }

    /// Whether the factory is creating a 64-bit PE
    pub fn is_64bit(&self) -> bool {
        self.ptr.is_64bit()
    }

    /// Return the section alignment
    pub fn section_align(&self) -> u32 {
        self.ptr.section_align()
    }

    /// Return the file alignment
    pub fn file_align(&self) -> u32 {
        self.ptr.file_align()
    }
}

impl std::fmt::Debug for Factory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Factory")
            .finish()
    }
}
