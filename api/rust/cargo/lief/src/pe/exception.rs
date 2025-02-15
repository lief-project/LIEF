//! Module for the PE exception support

use lief_ffi as ffi;
use super::exception_x64;
use super::exception_aarch64;

use crate::common::FromFFI;

/// Enum that wraps the different kinds of runtime functions associated with exceptions
#[derive(Debug)]
pub enum RuntimeExceptionFunction<'a> {
    /// An x86_64 exception entry
    X86_64(exception_x64::RuntimeFunction<'a>),

    /// An ARM64 exception entry
    AArch64(exception_aarch64::RuntimeFunction<'a>),
}

impl<'a> FromFFI<ffi::PE_ExceptionInfo> for RuntimeExceptionFunction<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_ExceptionInfo>) -> Self {
        unsafe {
            let obj_ref = ffi_entry.as_ref().unwrap();
            if ffi::PE_RuntimeFunctionX64::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_ExceptionInfo>;
                    type To = cxx::UniquePtr<ffi::PE_RuntimeFunctionX64>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                RuntimeExceptionFunction::X86_64(exception_x64::RuntimeFunction::from_ffi(raw))
            } else if ffi::PE_RuntimeFunctionAArch64::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_ExceptionInfo>;
                    type To = cxx::UniquePtr<ffi::PE_RuntimeFunctionAArch64>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                RuntimeExceptionFunction::AArch64(exception_aarch64::RuntimeFunction::from_ffi(raw))
            } else {
                panic!("unsupported architecture");
            }
        }
    }
}

/// Trait shared by all runtime functions
pub trait ExceptionInfo {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::PE_ExceptionInfo;

    /// Function start address
    fn rva_start(&self) -> u32 {
        self.as_generic().rva_start()
    }
}

impl std::fmt::Display for &dyn ExceptionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}
