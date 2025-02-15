//! Module related to dynamic relocations (DVRT)

use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use std::marker::PhantomData;
use super::dynamic_fixups::DynamicFixup;

pub const IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE: u32 = 1u32;

pub const IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE: u32 = 2u32;

pub const IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER: u32 = 3u32;

pub const IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER: u32 = 4u32;

pub const IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH: u32 = 5u32;

pub const IMAGE_DYNAMIC_RELOCATION_ARM64X: u32 = 6u32;

pub const IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE: u32 = 7u32;

pub const IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER: u32 = 8u32;


/// This enum wraps the different versions of dynamic relocations:
///
/// - `IMAGE_DYNAMIC_RELOCATION32`
/// - `IMAGE_DYNAMIC_RELOCATION32_V2`
/// - `IMAGE_DYNAMIC_RELOCATION64`
/// - `IMAGE_DYNAMIC_RELOCATION64_V2`
#[derive(Debug)]
pub enum DynamicRelocation<'a> {
    /// Either `IMAGE_DYNAMIC_RELOCATION32` or `IMAGE_DYNAMIC_RELOCATION64`
    V1(DynamicRelocationV1<'a>),

    /// Either `IMAGE_DYNAMIC_RELOCATION32` or `IMAGE_DYNAMIC_RELOCATION64_V2`
    V2(DynamicRelocationV2<'a>),
}

impl std::fmt::Display for DynamicRelocation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DynamicRelocation::V1(v1) => {
                write!(f, "{}", v1.as_generic().to_string())
            }
            DynamicRelocation::V2(v2) => {
                write!(f, "{}", v2.as_generic().to_string())
            }
        }
    }
}

impl<'a> FromFFI<ffi::PE_DynamicRelocation> for DynamicRelocation<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_DynamicRelocation>) -> Self {
        unsafe {
            let obj_ref = ffi_entry.as_ref().unwrap();
            if ffi::PE_DynamicRelocationV1::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_DynamicRelocation>;
                    type To = cxx::UniquePtr<ffi::PE_DynamicRelocationV1>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                DynamicRelocation::V1(DynamicRelocationV1::from_ffi(raw))
            } else if ffi::PE_DynamicRelocationV2::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_DynamicRelocation>;
                    type To = cxx::UniquePtr<ffi::PE_DynamicRelocationV2>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                DynamicRelocation::V2(DynamicRelocationV2::from_ffi(raw))
            } else {
                panic!("unsupported version");
            }
        }
    }
}

/// Trait shared by all dynamic relocations
pub trait AsDynamicRelocation {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::PE_DynamicRelocation;

    /// Version of the structure
    fn version(&self) -> u32 {
        self.as_generic().version()
    }

    /// Symbol address. Some values have a special meaning and define how fixups are encoded
    fn symbol(&self) -> u64 {
        self.as_generic().symbol()
    }

    /// Return fixups information, where the interpretation may depend on the
    /// [`AsDynamicRelocation::symbol`]
    fn fixups(&self) -> Option<DynamicFixup> {
        into_optional(self.as_generic().fixups())
    }
}

/// This structure represents a dynamic relocation (`IMAGE_DYNAMIC_RELOCATION32` or
/// `IMAGE_DYNAMIC_RELOCATION64`)
pub struct DynamicRelocationV1<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicRelocationV1>,
    _owner: PhantomData<&'a ffi::PE_LoadConfiguration>,
}

impl<'a> FromFFI<ffi::PE_DynamicRelocationV1> for DynamicRelocationV1<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicRelocationV1>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsDynamicRelocation for DynamicRelocationV1<'_> {
    fn as_generic(&self) -> &ffi::PE_DynamicRelocation {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for DynamicRelocationV1<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicRelocationV1")
            .field("version", &self.version())
            .field("symbol", &self.symbol())
        .finish()
    }
}

impl std::fmt::Display for DynamicRelocationV1<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

/// This class represents a dynamic relocation (`IMAGE_DYNAMIC_RELOCATION64_V2` or
/// `IMAGE_DYNAMIC_RELOCATION32_V2`)
pub struct DynamicRelocationV2<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicRelocationV2>,
    _owner: PhantomData<&'a ffi::PE_LoadConfiguration>,
}

impl<'a> FromFFI<ffi::PE_DynamicRelocationV2> for DynamicRelocationV2<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicRelocationV2>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsDynamicRelocation for DynamicRelocationV2<'_> {
    fn as_generic(&self) -> &ffi::PE_DynamicRelocation {
        self.ptr.as_ref().unwrap().as_ref()
    }
}


impl std::fmt::Debug for DynamicRelocationV2<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicRelocationV1")
            .field("version", &self.version())
            .field("symbol", &self.symbol())
        .finish()
    }
}

impl std::fmt::Display for DynamicRelocationV2<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

impl AsDynamicRelocation for DynamicRelocation<'_> {
    fn as_generic(&self) -> &ffi::PE_DynamicRelocation {
        match &self {
            DynamicRelocation::V1(entry) => {
                entry.as_generic()
            }

            DynamicRelocation::V2(entry) => {
                entry.as_generic()
            }
        }
    }
}

impl std::fmt::Display for &dyn AsDynamicRelocation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}
