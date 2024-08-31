use lief_ffi as ffi;

use crate::{to_slice, to_result, Error};
use crate::common::FromFFI;

use std::fmt;
use std::marker::PhantomData;

/// This class represents a stub entry in sections like `__stubs,__auth_stubs`.
///
/// It wraps assembly instructions which are used to access the *got* where the
/// address of the symbol is resolved.
///
/// Example:
///
/// ```text
/// 0000000236a3c1bc: ___memcpy_chk
///   adrp            x17, #0x241513aa8
///   add             x17, x17, #0x241513aa8
///   ldr             x16, [x17]
///   braa            x16, x17
/// ```
pub struct Stub<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Stub>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}

impl Stub<'_> {
    /// The virtual address where the stub is located
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }

    /// The (raw) instructions of this entry as a slice of bytes
    pub fn raw(&self) -> &[u8] {
        to_slice!(self.ptr.raw());
    }

    ///
    /// For instance, given this stub:
    ///
    /// ```text
    /// 0x3eec: adrp    x16, #4096
    /// 0x3ef0: ldr     x16, [x16, #24]
    /// 0x3ef4: br      x16
    /// ```
    ///
    /// The function returns: `0x4018`.
    ///
    /// <div class="warning">This function is only available with LIEF's extended version</div>
    pub fn target(&self) -> Result<u64, Error> {
        to_result!(ffi::MachO_Stub::target, self);
    }
}

impl fmt::Debug for Stub<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stub")
            .field("address", &self.address())
            .finish()
    }
}


impl FromFFI<ffi::MachO_Stub> for Stub<'_> {
    fn from_ffi(stub: cxx::UniquePtr<ffi::MachO_Stub>) -> Self {
        Self {
            ptr: stub,
            _owner: PhantomData
        }
    }
}
