use lief_ffi as ffi;

use crate::pe::Relocation;
use crate::common::{into_optional, FromFFI};
use crate::{declare_fwd_iterator, declare_iterator, to_slice};
use std::marker::PhantomData;

/// This enum wraps the different fixups that can be associated with a
/// [`crate::pe::DynamicRelocation`]
#[derive(Debug)]
pub enum DynamicFixup<'a> {
    /// Entry when [`crate::pe::dynamic_relocation::AsDynamicRelocation::symbol`] is not
    /// a special value
    Generic(Generic<'a>),

    /// Entry when [`crate::pe::dynamic_relocation::AsDynamicRelocation::symbol`] is set
    /// to [`crate::pe::dynamic_relocation::IMAGE_DYNAMIC_RELOCATION_ARM64X`]
    Arm64X(Arm64X<'a>),

    /// Entry when [`crate::pe::dynamic_relocation::AsDynamicRelocation::symbol`] is set
    /// to [`crate::pe::dynamic_relocation::IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE`]
    FunctionOverride(FunctionOverride<'a>),

    /// Entry when [`crate::pe::dynamic_relocation::AsDynamicRelocation::symbol`] is set
    /// to [`crate::pe::dynamic_relocation::IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER`]
    ARM64Kernel(ARM64Kernel<'a>),

    /// Entry when [`crate::pe::dynamic_relocation::AsDynamicRelocation::symbol`] is set
    /// to [`crate::pe::dynamic_relocation::IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER`]
    ControlTransfer(ControlTransfer<'a>),

    /// Entry when [`crate::pe::dynamic_relocation::AsDynamicRelocation::symbol`] is set
    /// to a special value that is not supported by LIEF.
    Unknown(Unknown<'a>)
}

impl<'a> FromFFI<ffi::PE_DynamicFixup> for DynamicFixup<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_DynamicFixup>) -> Self {
        unsafe {
            let obj_ref = ffi_entry.as_ref().unwrap();
            if ffi::PE_DynamicFixupARM64Kernel::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_DynamicFixup>;
                    type To = cxx::UniquePtr<ffi::PE_DynamicFixupARM64Kernel>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                DynamicFixup::ARM64Kernel(ARM64Kernel::from_ffi(raw))
            } else if ffi::PE_DynamicFixupARM64X::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_DynamicFixup>;
                    type To = cxx::UniquePtr<ffi::PE_DynamicFixupARM64X>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                DynamicFixup::Arm64X(Arm64X::from_ffi(raw))
            } else if ffi::PE_DynamicFixupControlTransfer::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_DynamicFixup>;
                    type To = cxx::UniquePtr<ffi::PE_DynamicFixupControlTransfer>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                DynamicFixup::ControlTransfer(ControlTransfer::from_ffi(raw))
            } else if ffi::PE_DynamicFixupGeneric::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_DynamicFixup>;
                    type To = cxx::UniquePtr<ffi::PE_DynamicFixupGeneric>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                DynamicFixup::Generic(Generic::from_ffi(raw))
            } else if ffi::PE_DynamicFixupUnknown::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_DynamicFixup>;
                    type To = cxx::UniquePtr<ffi::PE_DynamicFixupUnknown>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                DynamicFixup::Unknown(Unknown::from_ffi(raw))
            } else if ffi::PE_FunctionOverride::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_DynamicFixup>;
                    type To = cxx::UniquePtr<ffi::PE_FunctionOverride>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                DynamicFixup::FunctionOverride(FunctionOverride::from_ffi(raw))
            } else {
                panic!("unsupported version");
            }
        }
    }
}

pub trait AsDynamicFixup {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::PE_DynamicFixup;
}

impl std::fmt::Display for DynamicFixup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DynamicFixup::Generic(fixup) => {
                write!(f, "{}", fixup.as_generic().to_string())
            }

            DynamicFixup::Arm64X(fixup) => {
                write!(f, "{}", fixup.as_generic().to_string())
            }

            DynamicFixup::FunctionOverride(fixup) => {
                write!(f, "{}", fixup.as_generic().to_string())
            }

            DynamicFixup::ARM64Kernel(fixup) => {
                write!(f, "{}", fixup.as_generic().to_string())
            }

            DynamicFixup::ControlTransfer(fixup) => {
                write!(f, "{}", fixup.as_generic().to_string())
            }

            DynamicFixup::Unknown(fixup) => {
                write!(f, "{}", fixup.as_generic().to_string())
            }
        }
    }
}

/// This structure represents a generic entry where fixups are regular
/// relocations: [`crate::pe::Relocation`]
pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicFixupGeneric>,
    _owner: PhantomData<&'a ffi::PE_DynamicRelocation>,
}

impl<'a> FromFFI<ffi::PE_DynamicFixupGeneric> for Generic<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicFixupGeneric>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsDynamicFixup for Generic<'_> {
    fn as_generic(&self) -> &ffi::PE_DynamicFixup {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Generic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generic")
        .finish()
    }
}

impl std::fmt::Display for Generic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

impl Generic<'_> {
    /// Iterator over the (regular) relocations
    pub fn relocations(&self) -> GenericRelocations {
        GenericRelocations::new(self.ptr.relocations())
    }
}

/// This structure represents the [`crate::pe::dynamic_relocation::IMAGE_DYNAMIC_RELOCATION_ARM64X`]
/// special value
pub struct Arm64X<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicFixupARM64X>,
    _owner: PhantomData<&'a ffi::PE_DynamicRelocation>,
}

impl<'a> FromFFI<ffi::PE_DynamicFixupARM64X> for Arm64X<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicFixupARM64X>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsDynamicFixup for Arm64X<'_> {
    fn as_generic(&self) -> &ffi::PE_DynamicFixup {
        self.ptr.as_ref().unwrap().as_ref()
    }
}


impl std::fmt::Debug for Arm64X<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Arm64X")
        .finish()
    }
}

impl std::fmt::Display for Arm64X<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

impl Arm64X<'_> {
    /// Iterator over the relocations
    pub fn relocations(&self) -> Arm64XRelocEntries {
        Arm64XRelocEntries::new(self.ptr.relocations())
    }
}

/// Structure that describes a relocation entry for [`Arm64X`]
pub struct Arm64XRelocEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicFixupARM64X_entry>,
    _owner: PhantomData<&'a ffi::PE_DynamicFixupARM64X>,
}

impl<'a> FromFFI<ffi::PE_DynamicFixupARM64X_entry> for Arm64XRelocEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicFixupARM64X_entry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}


pub const ARM64X_RELOC_ZERO_FILL: u32 = 0;

pub const ARM64X_RELOC_VALUE: u32 = 1;

pub const ARM64X_RELOC_DELTA: u32 = 2;

impl Arm64XRelocEntry<'_> {
    /// RVA where the fixup takes place
    pub fn rva(&self) -> u32 {
        self.ptr.rva()
    }

    pub fn size(&self) -> u32 {
        self.ptr.size()
    }

    /// If the fixup is [`ARM64X_RELOC_DELTA`], return the associated delta.
    pub fn value(&self) -> Option<i64> {
        if self.kind() != ARM64X_RELOC_DELTA {
            return None;
        }
        Some(self.ptr.value())
    }


    /// If the fixup is [`ARM64X_RELOC_VALUE`], return the associated bytes.
    pub fn bytes(&self) -> Option<&[u8]> {
        if self.kind() != ARM64X_RELOC_VALUE {
            return None;
        }
        unsafe {
            let raw = self.ptr.get_bytes();
            if raw.size > 0 {
                return Some(std::slice::from_raw_parts_mut(raw.ptr, raw.size as usize));
            }
            return Some(&[]);
        }
    }

    /// Fixup's kind can be either:
    ///
    /// - [`ARM64X_RELOC_ZERO_FILL`]
    /// - [`ARM64X_RELOC_VALUE`]
    /// - [`ARM64X_RELOC_DELTA`]
    pub fn kind(&self) -> u32 {
        self.ptr.get_type()
    }
}


/// This structure represents the
/// [`crate::pe::dynamic_relocation::IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE`] special value
pub struct FunctionOverride<'a> {
    ptr: cxx::UniquePtr<ffi::PE_FunctionOverride>,
    _owner: PhantomData<&'a ffi::PE_DynamicRelocation>,
}

impl<'a> FromFFI<ffi::PE_FunctionOverride> for FunctionOverride<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_FunctionOverride>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsDynamicFixup for FunctionOverride<'_> {
    fn as_generic(&self) -> &ffi::PE_DynamicFixup {
        self.ptr.as_ref().unwrap().as_ref()
    }
}


impl std::fmt::Debug for FunctionOverride<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionOverride")
        .finish()
    }
}

impl std::fmt::Display for FunctionOverride<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}



impl FunctionOverride<'_> {
    /// Iterator over the overriding info
    pub fn func_overriding_info(&self) -> ItFuncOverrideInfo {
        ItFuncOverrideInfo::new(self.ptr.func_overriding_info())
    }

    /// Find the `IMAGE_BDD_INFO` associated with the given info
    pub fn bdd_info(&self) -> ItImageBddInfo {
        ItImageBddInfo::new(self.ptr.bdd_info())
    }

    /// Find the `IMAGE_BDD_INFO` at the given offset
    pub fn bdd_info_at(&self, offset: u32) -> Option<ImageBddInfo> {
        into_optional(self.ptr.bdd_info_at(offset))
    }

    /// Find the `IMAGE_BDD_INFO` associated with the given info
    pub fn bdd_info_for(&self, info: &FunctionOverrideInfo) -> Option<ImageBddInfo> {
        into_optional(self.ptr.bdd_info_for(info.ptr.as_ref().unwrap()))
    }
}

/// Mirror `IMAGE_BDD_DYNAMIC_RELOCATION`
pub struct ImageBddDynamicRelocation<'a> {
    ptr: cxx::UniquePtr<ffi::PE_FunctionOverride_image_bdd_dynamic_relocation_t>,
    _owner: PhantomData<&'a ffi::PE_FunctionOverride>,
}

impl<'a> FromFFI<ffi::PE_FunctionOverride_image_bdd_dynamic_relocation_t> for ImageBddDynamicRelocation<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_FunctionOverride_image_bdd_dynamic_relocation_t>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl ImageBddDynamicRelocation<'_> {
    pub fn left(&self) -> u16 {
        self.ptr.left()
    }

    pub fn right(&self) -> u16 {
        self.ptr.right()
    }

    pub fn value(&self) -> u32 {
        self.ptr.value()
    }
}

/// Mirror `IMAGE_BDD_INFO`
pub struct ImageBddInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_FunctionOverride_image_bdd_info_t>,
    _owner: PhantomData<&'a ffi::PE_FunctionOverride>,
}

impl<'a> FromFFI<ffi::PE_FunctionOverride_image_bdd_info_t> for ImageBddInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_FunctionOverride_image_bdd_info_t>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl ImageBddInfo<'_> {
    pub fn version(&self) -> u32 {
        self.ptr.version()
    }

    pub fn original_size(&self) -> u32 {
        self.ptr.original_size()
    }

    pub fn original_offset(&self) -> u32 {
        self.ptr.original_offset()
    }

    /// If [`ImageBddInfo::version`] is 1
    pub fn payload(&self) -> &[u8] {
        to_slice!(self.ptr.payload());
    }

    /// If [`ImageBddInfo::version`] is not 1
    pub fn relocations(&self) -> ImageBddDynRelocations {
        ImageBddDynRelocations::new(self.ptr.relocations())
    }
}

pub struct FunctionOverrideInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_FunctionOverrideInfo>,
    _owner: PhantomData<&'a ffi::PE_FunctionOverride>,
}

impl<'a> FromFFI<ffi::PE_FunctionOverrideInfo> for FunctionOverrideInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_FunctionOverrideInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl FunctionOverrideInfo<'_> {
    /// RVA of the original function
    pub fn original_rva(&self) -> u32 {
        self.ptr.original_rva()
    }

    /// Offset into the BDD region
    pub fn bdd_offset(&self) -> u32 {
        self.ptr.bdd_offset()
    }

    /// Size in bytes taken by RVAs
    pub fn rva_size(&self) -> u32 {
        self.ptr.rva_size()
    }

    /// Size in bytes taken by BaseRelocs
    pub fn base_reloc_size(&self) -> u32 {
        self.ptr.base_reloc_size()
    }

    pub fn functions_rva(&self) -> Vec<u32> {
        Vec::from(self.ptr.functions_rva().as_slice())
    }

    pub fn relocations(&self) -> FuncOverrideRelocations {
        FuncOverrideRelocations::new(self.ptr.relocations())
    }
}

/// This class wraps fixups associated with the (special) symbol value:
/// [`crate::pe::dynamic_relocation::IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER`].
pub struct ARM64Kernel<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicFixupARM64Kernel>,
    _owner: PhantomData<&'a ffi::PE_DynamicRelocation>,
}

impl<'a> FromFFI<ffi::PE_DynamicFixupARM64Kernel> for ARM64Kernel<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicFixupARM64Kernel>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsDynamicFixup for ARM64Kernel<'_> {
    fn as_generic(&self) -> &ffi::PE_DynamicFixup {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for ARM64Kernel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ARM64Kernel")
        .finish()
    }
}

impl std::fmt::Display for ARM64Kernel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

impl ARM64Kernel<'_> {
    /// Iterator over the different relocations
    pub fn relocations(&self) -> ARM64KernelEntries {
        ARM64KernelEntries::new(self.ptr.relocations())
    }
}

/// Mirror `IMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION`
pub struct ARM64KernelEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicFixupARM64Kernel_entry>,
    _owner: PhantomData<&'a ffi::PE_DynamicFixupARM64Kernel>,
}

impl<'a> FromFFI<ffi::PE_DynamicFixupARM64Kernel_entry> for ARM64KernelEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicFixupARM64Kernel_entry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl ARM64KernelEntry<'_> {
    /// RVA to the call instruction
    pub fn rva(&self) -> u32 {
        self.ptr.rva()
    }

    /// True if target instruction is a `blr`, false if it's a `br`.
    pub fn indirect_call(&self) -> bool {
        self.ptr.indirect_call()
    }

    /// Register index used for the indirect call/jump.
    /// For instance, if the instruction is `br x3`, this index is set to `3`
    pub fn register_index(&self) -> u8 {
        self.ptr.register_index()
    }

    /// IAT index of the corresponding import. `0x7FFF` is a special value
    /// indicating no index.
    pub fn iat_index(&self) -> u16 {
        self.ptr.iat_index()
    }
}

/// This class wraps fixups associated with the (special) symbol value:
/// [`crate::pe::dynamic_relocation::IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER`].
pub struct ControlTransfer<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicFixupControlTransfer>,
    _owner: PhantomData<&'a ffi::PE_DynamicRelocation>,
}

impl<'a> FromFFI<ffi::PE_DynamicFixupControlTransfer> for ControlTransfer<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicFixupControlTransfer>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsDynamicFixup for ControlTransfer<'_> {
    fn as_generic(&self) -> &ffi::PE_DynamicFixup {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for ControlTransfer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlTransfer")
        .finish()
    }
}

impl std::fmt::Display for ControlTransfer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

impl ControlTransfer<'_> {
    /// Iterator over the relocations
    pub fn relocations(&self) -> ControlTransferEntries {
        ControlTransferEntries::new(self.ptr.relocations())
    }
}

/// Mirror `IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION`
pub struct ControlTransferEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicFixupControlTransfer_entry>,
    _owner: PhantomData<&'a ffi::PE_DynamicFixupControlTransfer>,
}

impl<'a> FromFFI<ffi::PE_DynamicFixupControlTransfer_entry> for ControlTransferEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicFixupControlTransfer_entry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl ControlTransferEntry<'_> {
    /// RVA to the call instruction
    pub fn rva(&self) -> u32 {
        self.ptr.rva()
    }

    /// True if target instruction is a `call`, false otherwise.
    pub fn is_call(&self) -> bool {
        self.ptr.is_call()
    }

    /// IAT index of the corresponding import. `0x7FFF` is a special value
    /// indicating no index.
    pub fn iat_index(&self) -> u16 {
        self.ptr.iat_index()
    }
}


/// This class represents an special dynamic relocation where the format of the
/// fixups is not supported by LIEF.
pub struct Unknown<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DynamicFixupUnknown>,
    _owner: PhantomData<&'a ffi::PE_DynamicRelocation>,
}

impl<'a> FromFFI<ffi::PE_DynamicFixupUnknown> for Unknown<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DynamicFixupUnknown>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsDynamicFixup for Unknown<'_> {
    fn as_generic(&self) -> &ffi::PE_DynamicFixup {
        self.ptr.as_ref().unwrap().as_ref()
    }
}


impl std::fmt::Debug for Unknown<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unknown")
        .finish()
    }
}

impl std::fmt::Display for Unknown<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

impl Unknown<'_> {
    pub fn payload(&self) -> &[u8] {
        to_slice!(self.ptr.payload());
    }
}

declare_iterator!(
    ARM64KernelEntries,
    ARM64KernelEntry<'a>,
    ffi::PE_DynamicFixupARM64Kernel_entry,
    ffi::PE_DynamicFixupARM64Kernel,
    ffi::PE_DynamicFixupARM64Kernel_it_relocations
);

declare_iterator!(
    Arm64XRelocEntries,
    Arm64XRelocEntry<'a>,
    ffi::PE_DynamicFixupARM64X_entry,
    ffi::PE_DynamicFixupARM64X,
    ffi::PE_DynamicFixupARM64X_it_relocations
);

declare_iterator!(
    ControlTransferEntries,
    ControlTransferEntry<'a>,
    ffi::PE_DynamicFixupControlTransfer_entry,
    ffi::PE_DynamicFixupControlTransfer,
    ffi::PE_DynamicFixupControlTransfer_it_relocations
);

declare_iterator!(
    GenericRelocations,
    Relocation<'a>,
    ffi::PE_Relocation,
    ffi::PE_DynamicFixupGeneric,
    ffi::PE_DynamicFixupGeneric_it_relocations
);

declare_fwd_iterator!(
    ImageBddDynRelocations,
    ImageBddDynamicRelocation<'a>,
    ffi::PE_FunctionOverride_image_bdd_dynamic_relocation_t,
    ffi::PE_FunctionOverride_image_bdd_info_t,
    ffi::PE_FunctionOverride_image_bdd_info_t_it_relocations
);

declare_iterator!(
    FuncOverrideRelocations,
    Relocation<'a>,
    ffi::PE_Relocation,
    ffi::PE_FunctionOverrideInfo,
    ffi::PE_FunctionOverrideInfo_it_relocations
);

declare_iterator!(
    ItFuncOverrideInfo,
    FunctionOverrideInfo<'a>,
    ffi::PE_FunctionOverrideInfo,
    ffi::PE_FunctionOverride,
    ffi::PE_FunctionOverride_it_func_overriding_info
);

declare_iterator!(
    ItImageBddInfo,
    ImageBddInfo<'a>,
    ffi::PE_FunctionOverride_image_bdd_info_t,
    ffi::PE_FunctionOverride,
    ffi::PE_FunctionOverride_it_bdd_info
);



