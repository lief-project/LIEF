use lief_ffi as ffi;
use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::elf::note::NoteBase;
use crate::{to_result, Error};

/// Note representing core signal information (`NT_SIGINFO`)
pub struct SigInfo<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_CoreSigInfo>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl SigInfo<'_> {
    /// Signal number
    pub fn signo(&self) -> Result<i32, Error> {
        to_result!(ffi::ELF_CoreSigInfo::signo, &self);
    }

    /// Signal code
    pub fn sigcode(&self) -> Result<i32, Error> {
        to_result!(ffi::ELF_CoreSigInfo::sigcode, &self);
    }

    /// Signal error number
    pub fn sigerrno(&self) -> Result<i32, Error> {
        to_result!(ffi::ELF_CoreSigInfo::sigerrno, &self);
    }
}

impl NoteBase for SigInfo<'_> {
    fn get_base(&self) -> &ffi::ELF_Note {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_CoreSigInfo> for SigInfo<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_CoreSigInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for SigInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn NoteBase;
        f.debug_struct("CoreSigInfo")
            .field("base", &base)
            //.field("signo", &self.signo())
            //.field("sigcode", &self.sigcode())
            //.field("sigerrno", &self.sigerrno())
            .finish()
    }
}
