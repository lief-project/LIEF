use lief_ffi as ffi;
use std::marker::PhantomData;

use super::NoteBase;
use crate::common::FromFFI;
use crate::enum_from_int;

enum_from_int! {
    #[allow(non_camel_case_types)]
    /// ABI type for the note
    Abi: u32 {
        LINUX = 0,
        GNU = 1,
        SOLARIS2 = 2,
        FREEBSD = 3,
        NETBSD = 4,
        SYLLABLE = 5,
        NACL = 6,
    }
}

/// Note representing an ABI tag (e.g. `NT_GNU_ABI_TAG`)
pub struct NoteAbi<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteAbi>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl NoteAbi<'_> {
    /// Return the ABI
    pub fn abi(&self) -> Abi {
        Abi::from(self.ptr.abi())
    }

    /// Return the version as `[major, minor, patch]`
    pub fn version(&self) -> Vec<u64> {
        Vec::from(self.ptr.version().as_slice())
    }
}

impl NoteBase for NoteAbi<'_> {
    fn get_base(&self) -> &ffi::ELF_Note {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteAbi> for NoteAbi<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteAbi>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for NoteAbi<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn NoteBase;
        f.debug_struct("NoteAbi")
            .field("base", &base)
            .field("abi", &self.abi())
            .field("version", &self.version())
            .finish()
    }
}
