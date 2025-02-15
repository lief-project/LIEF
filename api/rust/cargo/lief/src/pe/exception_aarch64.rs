//! This module contains structures related to the ARM64 exception support in PE files

use lief_ffi as ffi;

use std::marker::PhantomData;

use super::ExceptionInfo;

use crate::common::FromFFI;
use crate::{declare_iterator, to_slice};

/// This enum represents an entry in the exception table (`.pdata` section) for the AArch64
/// architecture.
///
/// Since the ARM64 unwinding info can be encoded in a *packed* and *unpacked* format, this enums
/// wraps two entries [`Packed`] and [`Unpacked`].
///
/// Reference: <https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#arm64-exception-handling-information>
#[derive(Debug)]
pub enum RuntimeFunction<'a> {
    /// A packed exception entry that fits on 30 bits
    Packed(Packed<'a>),

    /// An extended exception entry that has variable length data
    Unpacked(Unpacked<'a>),
}

impl<'a> FromFFI<ffi::PE_RuntimeFunctionAArch64> for RuntimeFunction<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_RuntimeFunctionAArch64>) -> Self {
        unsafe {
            let obj_ref = ffi_entry.as_ref().unwrap();
            if ffi::PE_unwind_aarch64_UnpackedFunction::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_RuntimeFunctionAArch64>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_aarch64_UnpackedFunction>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                RuntimeFunction::Unpacked(Unpacked::from_ffi(raw))
            } else if ffi::PE_unwind_aarch64_PackedFunction::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_RuntimeFunctionAArch64>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_aarch64_PackedFunction>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                RuntimeFunction::Packed(Packed::from_ffi(raw))
            } else {
                panic!("unsupported format: {}", obj_ref.as_ref().to_string());
            }
        }
    }
}

impl ExceptionInfo for RuntimeFunction<'_> {
    fn as_generic(&self) -> &ffi::PE_ExceptionInfo {
        match &self {
            RuntimeFunction::Packed(f) => f.as_generic(),
            RuntimeFunction::Unpacked(f) => f.as_generic(),
        }
    }
}

/// This structure represents a packed AArch64 exception entry.
///
/// An excepted entry can be packed if the unwind data fit in 30 bits
///
/// Reference: <https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170#packed-unwind-data>
pub struct Packed<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_aarch64_PackedFunction>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl<'a> FromFFI<ffi::PE_unwind_aarch64_PackedFunction> for Packed<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_aarch64_PackedFunction>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Packed<'_> {
    /// Size of the allocated stack
    pub fn frame_size(&self) -> u8 {
        self.ptr.frame_size()
    }

    /// Number of non-volatile INT registers (x19-x28) saved in the canonical stack location.
    #[allow(non_snake_case)]
    pub fn reg_I(&self) -> u8 {
        self.ptr.reg_I()
    }

    /// Number of non-volatile FP registers (d8-d15) saved in the canonical stack location
    #[allow(non_snake_case)]
    pub fn reg_F(&self) -> u8 {
        self.ptr.reg_F()
    }

    /// 1-bit flag indicating whether the function homes the integer parameter registers (x0-x7) by
    /// storing them at the very start of the function.
    /// (0 = doesn't home registers, 1 = homes registers).
    #[allow(non_snake_case)]
    pub fn H(&self) -> u8 {
        self.ptr.H()
    }

    /// Flag indicating whether the function includes extra instructions to set up a frame chain
    /// and return link.
    #[allow(non_snake_case)]
    pub fn CR(&self) -> u8 {
        self.ptr.CR()
    }
}

impl ExceptionInfo for Packed<'_> {
    fn as_generic(&self) -> &ffi::PE_ExceptionInfo {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl std::fmt::Debug for Packed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Packed")
            .field("frame_size", &self.frame_size())
            .field("RI", &self.reg_I())
            .field("RF", &self.reg_F())
            .field("H", &self.H())
            .field("CR", &self.CR())
            .finish()
    }
}

/// This class represents an unpacked AArch64 exception entry
///
/// Reference: <https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170#xdata-records>
pub struct Unpacked<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_aarch64_UnpackedFunction>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl<'a> FromFFI<ffi::PE_unwind_aarch64_UnpackedFunction> for Unpacked<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_aarch64_UnpackedFunction>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Unpacked<'_> {
    /// RVA where this unpacked data is located (usually pointing in `.xdata`)
    pub fn xdata_rva(&self) -> u32 {
        self.ptr.xdata_rva()
    }

    /// Describes the version of the remaining `.xdata`.
    ///
    /// Currently (2025-01-04), only version 0 is defined, so values of 1-3 aren't
    /// permitted.
    pub fn version(&self) -> u32 {
        self.ptr.version()
    }

    /// 1-bit field that indicates the presence (1) or absence (0) of exception
    /// data.
    #[allow(non_snake_case)]
    pub fn X(&self) -> u8 {
        self.ptr.X()
    }

    /// 1-bit field that indicates that information describing a single epilog is
    /// packed into the header (1) rather than requiring more scope words later (0).
    #[allow(non_snake_case)]
    pub fn E(&self) -> u8 {
        self.ptr.E()
    }

    /// If [`Unpacked::E`] == 0, specifies the count of the total number of epilog scopes.
    /// Otherwise, return 0
    pub fn epilog_count(&self) -> u16 {
        self.ptr.epilog_count()
    }

    /// **If E() == 1**, index of the first unwind code that describes the one and
    /// only epilog.
    pub fn epilog_offset(&self) -> u16 {
        self.ptr.epilog_offset()
    }

    /// Number of 32-bit words needed to contain all of the unwind codes
    pub fn code_words(&self) -> u32 {
        self.ptr.code_words()
    }

    /// Exception handler RVA (if any)
    pub fn exception_handler(&self) -> u32 {
        self.ptr.exception_handler()
    }

    /// Slices that contain the unwind codes.
    pub fn unwind_code(&self) -> &[u8] {
        to_slice!(self.ptr.unwind_code());
    }

    /// Iterator over the epilog scopes
    pub fn epilog_scopes(&self) -> EpilogScopes {
        EpilogScopes::new(self.ptr.epilog_scopes())
    }
}

impl ExceptionInfo for Unpacked<'_> {
    fn as_generic(&self) -> &ffi::PE_ExceptionInfo {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl std::fmt::Debug for Unpacked<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unpacked")
            .field("xdata_rva", &self.xdata_rva())
            .field("version", &self.version())
            .field("X", &self.X())
            .field("E", &self.E())
            .field("epilog_count", &self.epilog_count())
            .field("epilog_offset", &self.epilog_offset())
            .field("code_words", &self.code_words())
            .field("exception_handler", &self.exception_handler())
            .finish()
    }
}

/// This strucure describes an epilog scope.
pub struct EpilogScope<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_aarch64_UnpackedFunction_epilog_scope_t>,
    _owner: PhantomData<&'a ffi::PE_unwind_aarch64_UnpackedFunction>,
}

impl<'a> FromFFI<ffi::PE_unwind_aarch64_UnpackedFunction_epilog_scope_t> for EpilogScope<'a> {
    fn from_ffi(
        ptr: cxx::UniquePtr<ffi::PE_unwind_aarch64_UnpackedFunction_epilog_scope_t>,
    ) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl EpilogScope<'_> {
    /// Offset of the epilog relatives to the start of the function
    pub fn start_offset(&self) -> u32 {
        self.ptr.start_offset()
    }

    /// Byte index of the first unwind code that describes this epilog
    pub fn start_index(&self) -> u16 {
        self.ptr.start_index()
    }

    /// Reserved for future expansion. Should be 0.
    pub fn reserved(&self) -> u8 {
        self.ptr.reserved()
    }
}

impl std::fmt::Debug for EpilogScope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpilogScope")
            .field("start_offset", &self.start_offset())
            .field("start_index", &self.start_index())
            .field("reserved", &self.reserved())
            .finish()
    }
}

declare_iterator!(
    EpilogScopes,
    EpilogScope<'a>,
    ffi::PE_unwind_aarch64_UnpackedFunction_epilog_scope_t,
    ffi::PE_unwind_aarch64_UnpackedFunction,
    ffi::PE_unwind_aarch64_UnpackedFunction_it_const_epilog_scopes
);
