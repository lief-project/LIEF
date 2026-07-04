use super::Command;
use crate::common::FromFFI;
use lief_ffi as ffi;
use std::marker::PhantomData;

/// Structure that represents the LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 commands
///
/// The encryption info is usually present in Mach-O executables that
/// target iOS to encrypt some sections of the binary
pub struct EncryptionInfo<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_EncryptionInfo>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl EncryptionInfo<'_> {
    /// The beginning of the encrypted area
    pub fn crypt_offset(&self) -> u32 {
        self.ptr.crypt_offset()
    }

    /// The size of the encrypted area
    pub fn crypt_size(&self) -> u32 {
        self.ptr.crypt_size()
    }

    /// The encryption system. 0 means no encrypted
    pub fn crypt_id(&self) -> u32 {
        self.ptr.crypt_id()
    }
}

impl std::fmt::Debug for EncryptionInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("EncryptionInfo")
            .field("base", &base)
            .field("crypt_id", &self.crypt_id())
            .field("crypt_offset", &self.crypt_offset())
            .field("crypt_size", &self.crypt_size())
            .finish()
    }
}

impl FromFFI<ffi::MachO_EncryptionInfo> for EncryptionInfo<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_EncryptionInfo>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for EncryptionInfo<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
