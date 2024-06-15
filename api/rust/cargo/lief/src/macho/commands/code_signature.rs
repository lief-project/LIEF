use super::Command;
use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::to_slice;
use std::marker::PhantomData;


/// Structure that represents the `LC_CODE_SIGNATURE` command
pub struct CodeSignature<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_CodeSignature>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl CodeSignature<'_> {
    /// Offset in the binary where the signature starts
    pub fn data_offset(&self) -> u32 {
        self.ptr.data_offset()
    }

    /// Size of the raw signature
    pub fn data_size(&self) -> u32 {
        self.ptr.data_size()
    }

    /// Content of the signature as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
}

impl std::fmt::Debug for CodeSignature<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("CodeSignature")
            .field("base", &base)
            .field("data_offset", &self.data_offset())
            .field("data_size", &self.data_size())
            .finish()
    }
}

impl FromFFI<ffi::MachO_CodeSignature> for CodeSignature<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_CodeSignature>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for CodeSignature<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
