//! PE enclave configuration
use std::marker::PhantomData;

use crate::{common::FromFFI, declare_iterator, to_slice};
use lief_ffi as ffi;

/// Defines an entry in the array of images that an enclave can import.
pub struct EnclaveConfiguration<'a> {
    ptr: cxx::UniquePtr<ffi::PE_EnclaveConfiguration>,
    _owner: PhantomData<&'a ffi::PE_LoadConfiguration>,
}

impl EnclaveConfiguration<'_> {
    /// The size of the `IMAGE_ENCLAVE_CONFIG64/IMAGE_ENCLAVE_CONFIG32` structure, in bytes.
    pub fn size(&self) -> u32 {
        self.ptr.size()
    }

    /// The minimum size of the `IMAGE_ENCLAVE_CONFIG(32,64)` structure that the
    /// image loader must be able to process in order for the enclave to be usable.
    ///
    /// This member allows an enclave to inform an earlier version of the image
    /// loader that the image loader can safely load the enclave and ignore
    /// optional members added to `IMAGE_ENCLAVE_CONFIG(32,64)` for later versions
    /// of the enclave. If the size of `IMAGE_ENCLAVE_CONFIG(32,64)` that the image
    /// loader can process is less than `MinimumRequiredConfigSize`, the enclave
    /// cannot be run securely.
    ///
    /// If `MinimumRequiredConfigSize` is zero, the minimum size of the
    /// `IMAGE_ENCLAVE_CONFIG(32,64)` structure that the image loader must be able
    /// to process in order for the enclave to be usable is assumed to be the size
    /// of the structure through and including the `MinimumRequiredConfigSize` member.
    pub fn min_required_config_size(&self) -> u32 {
        self.ptr.min_required_config_size()
    }

    /// A flag that indicates whether the enclave permits debugging.
    pub fn policy_flags(&self) -> u32 {
        self.ptr.policy_flags()
    }

    /// Whether this enclave can be debugged
    pub fn is_debuggable(&self) -> bool {
        self.ptr.is_debuggable()
    }

    /// The RVA of the array of images that the enclave image may import, with identity information
    /// for each image.
    pub fn import_list_rva(&self) -> u32 {
        self.ptr.import_list_rva()
    }

    /// The size of each image in the array of images that the [`EnclaveConfiguration::import_list_rva`]
    /// member points to.
    pub fn import_entry_size(&self) -> u32 {
        self.ptr.import_entry_size()
    }

    /// The number of images in the array of images that the [`EnclaveConfiguration::import_list_rva`]
    /// member points to.
    pub fn nb_imports(&self) -> u32 {
        self.ptr.nb_imports()
    }

    /// Return an iterator over the enclave's imports
    pub fn imports(&self) -> Imports {
        Imports::new(self.ptr.imports())
    }

    /// The family identifier that the author of the enclave assigned to the enclave.
    pub fn family_id(&self) -> &[u8] {
        to_slice!(self.ptr.family_id());
    }

    /// The image identifier that the author of the enclave assigned to the enclave.
    pub fn image_id(&self) -> &[u8] {
        to_slice!(self.ptr.image_id());
    }

    /// The version number that the author of the enclave assigned to the enclave.
    pub fn image_version(&self) -> u32 {
        self.ptr.image_version()
    }

    /// The security version number that the author of the enclave assigned to the enclave.
    pub fn security_version(&self) -> u32 {
        self.ptr.security_version()
    }

    /// The expected virtual size of the private address range for the enclave, in bytes.
    pub fn enclave_size(&self) -> u64 {
        self.ptr.enclave_size()
    }

    /// The maximum number of threads that can be created within the enclave.
    pub fn nb_threads(&self) -> u32 {
        self.ptr.nb_threads()
    }

    /// A flag that indicates whether the image is suitable for use as the primary image in the
    /// enclave.
    pub fn enclave_flags(&self) -> u32 {
        self.ptr.enclave_flags()
    }
}

impl std::fmt::Debug for EnclaveConfiguration<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnclaveConfiguration")
            .field("size", &self.size())
            .field("min_required_config_size", &self.min_required_config_size())
            .field("policy_flags", &self.policy_flags())
            .field("is_debuggable", &self.is_debuggable())
            .field("import_list_rva", &self.import_list_rva())
            .field("import_entry_size", &self.import_entry_size())
            .field("nb_imports", &self.nb_imports())
            .field("family_id", &self.family_id())
            .field("image_version", &self.image_version())
            .field("security_version", &self.security_version())
            .field("enclave_size", &self.enclave_size())
            .field("nb_threads", &self.nb_threads())
            .field("enclave_flags", &self.enclave_flags())
            .finish()
    }
}

impl std::fmt::Display for EnclaveConfiguration<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

impl<'a> FromFFI<ffi::PE_EnclaveConfiguration> for EnclaveConfiguration<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_EnclaveConfiguration>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}


/// This structure represents an entry in the array of images that an enclave can import.
pub struct EnclaveImport<'a> {
    ptr: cxx::UniquePtr<ffi::PE_EnclaveImport>,
    _owner: PhantomData<&'a ffi::PE_EnclaveConfiguration>,
}

impl EnclaveImport<'_> {
    /// The type of identifier of the image that must match the value in the import record.
    pub fn get_type(&self) -> Type {
        Type::from(self.ptr.get_type())
    }

    /// The minimum enclave security version that each image must have for the
    /// image to be imported successfully. The image is rejected unless its enclave
    /// security version is equal to or greater than the minimum value in the
    /// import record. Set the value in the import record to zero to turn off the
    /// security version check.
    pub fn min_security_version(&self) -> u32 {
        self.ptr.min_security_version()
    }

    /// The relative virtual address of a NULL-terminated string that contains the
    /// same value found in the import directory for the image.
    pub fn import_name_rva(&self) -> u32 {
        self.ptr.import_name_rva()
    }

    /// Resolved import name
    pub fn import_name(&self) -> String {
        self.ptr.import_name().to_string()
    }

    /// Reserved. Should be 0
    pub fn reserved(&self) -> u32 {
        self.ptr.reserved()
    }

    /// The unique identifier of the primary module for the enclave, if the
    /// [`EnclaveImport::get_type`] is [`Type::UNIQUE_ID`]. Otherwise, the author identifier of the
    /// primary module for the enclave.
    pub fn id(&self) -> &[u8] {
        to_slice!(self.ptr.id());
    }

    /// The family identifier of the primary module for the enclave.
    pub fn family_id(&self) -> &[u8] {
        to_slice!(self.ptr.family_id());
    }

    /// The image identifier of the primary module for the enclave.
    pub fn image_id(&self) -> &[u8] {
        to_slice!(self.ptr.image_id());
    }
}

impl std::fmt::Debug for EnclaveImport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnclaveImport")
            .field("type", &self.get_type())
            .field("min_security_version", &self.min_security_version())
            .field("import_name_rva", &self.import_name_rva())
            .field("import_name", &self.import_name())
            .field("reserved", &self.reserved())
            .field("id", &self.id())
            .field("family_id", &self.family_id())
            .field("image_id", &self.image_id())
            .finish()
    }
}

impl std::fmt::Display for EnclaveImport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

impl<'a> FromFFI<ffi::PE_EnclaveImport> for EnclaveImport<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_EnclaveImport>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum Type {
    /// None of the identifiers of the image need to match the value in the
    /// import record.
    NONE,

    /// The value of the enclave unique identifier of the image must match the
    /// value in the import record. Otherwise, loading of the image fails.
    UNIQUE_ID,

    /// The value of the enclave author identifier of the image must match the
    /// value in the import record. Otherwise, loading of the image fails. If
    /// this flag is set and the import record indicates an author identifier
    /// of all zeros, the imported image must be part of the Windows installation.
    AUTHOR_ID,

 	  /// The value of the enclave family identifier of the image must match the
    /// value in the import record. Otherwise, loading of the image fails.
    FAMILY_ID,

    /// The value of the enclave image identifier of the image must match the
    /// value in the import record. Otherwise, loading of the image fails.
    IMAGE_ID,
    UNKNOWN(u32),
}

impl From<u32> for Type {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Type::NONE,
            0x00000001 => Type::UNIQUE_ID,
            0x00000002 => Type::AUTHOR_ID,
            0x00000003 => Type::FAMILY_ID,
            0x00000004 => Type::IMAGE_ID,
            _ => Type::UNKNOWN(value),
        }
    }
}

declare_iterator!(
    Imports,
    EnclaveImport<'a>,
    ffi::PE_EnclaveImport,
    ffi::PE_EnclaveConfiguration,
    ffi::PE_EnclaveConfiguration_it_imports
);


