use lief_ffi as ffi;
use std::marker::PhantomData;

use super::NoteBase;
use crate::common::FromFFI;

/// Note representing the `.note.android.ident` section
pub struct AndroidIdent<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_AndroidIdent>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl AndroidIdent<'_> {
    /// Target SDK version (or 0 if it can't be resolved)
    pub fn sdk_version(&self) -> u32 {
        self.ptr.sdk_version()
    }

    /// NDK version used (or an empty string if it can't be parsed)
    pub fn ndk_version(&self) -> String {
        self.ptr.ndk_version().to_string()
    }

    /// NDK build number (or an empty string if it can't be parsed)
    pub fn ndk_build_number(&self) -> String {
        self.ptr.ndk_build_number().to_string()
    }
}

impl NoteBase for AndroidIdent<'_> {
    fn get_base(&self) -> &ffi::ELF_Note {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_AndroidIdent> for AndroidIdent<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_AndroidIdent>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for AndroidIdent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn NoteBase;
        f.debug_struct("AndroidIdent")
            .field("base", &base)
            .field("sdk_version", &self.sdk_version())
            .field("ndk_version", &self.ndk_version())
            .field("ndk_build_number", &self.ndk_build_number())
            .finish()
    }
}
