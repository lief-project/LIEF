use lief_ffi as ffi;
use std::marker::PhantomData;

use super::NoteBase;
use crate::common::FromFFI;

/// Note representing the QNX stack information
pub struct QNXStack<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_QNXStack>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl QNXStack<'_> {
    /// The stack size
    pub fn stack_size(&self) -> u32 {
        self.ptr.stack_size()
    }

    /// The stack allocated size
    pub fn stack_allocated(&self) -> u32 {
        self.ptr.stack_allocated()
    }

    /// Whether the stack is executable
    pub fn is_executable(&self) -> bool {
        self.ptr.is_executable()
    }
}

impl NoteBase for QNXStack<'_> {
    fn get_base(&self) -> &ffi::ELF_Note {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_QNXStack> for QNXStack<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_QNXStack>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for QNXStack<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn NoteBase;
        f.debug_struct("QNXStack")
            .field("base", &base)
            .field("stack_size", &self.stack_size())
            .field("stack_allocated", &self.stack_allocated())
            .field("is_executable", &self.is_executable())
            .finish()
    }
}
