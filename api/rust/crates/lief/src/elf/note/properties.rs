use lief_ffi as ffi;
use std::marker::PhantomData;

use crate::common::FromFFI;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Type of the GNU property
pub enum PropertyType {
    UNKNOWN,
    GENERIC,
    AARCH64_FEATURES,
    AARCH64_PAUTH,
    STACK_SIZE,
    NO_COPY_ON_PROTECTED,
    X86_ISA,
    X86_FEATURE,
    NEEDED,
}

impl From<u32> for PropertyType {
    fn from(value: u32) -> Self {
        match value {
            0 => PropertyType::UNKNOWN,
            1 => PropertyType::GENERIC,
            2 => PropertyType::AARCH64_FEATURES,
            3 => PropertyType::AARCH64_PAUTH,
            4 => PropertyType::STACK_SIZE,
            5 => PropertyType::NO_COPY_ON_PROTECTED,
            6 => PropertyType::X86_ISA,
            7 => PropertyType::X86_FEATURE,
            8 => PropertyType::NEEDED,
            _ => PropertyType::UNKNOWN,
        }
    }
}

impl From<PropertyType> for u32 {
    fn from(value: PropertyType) -> u32 {
        match value {
            PropertyType::UNKNOWN => 0,
            PropertyType::GENERIC => 1,
            PropertyType::AARCH64_FEATURES => 2,
            PropertyType::AARCH64_PAUTH => 3,
            PropertyType::STACK_SIZE => 4,
            PropertyType::NO_COPY_ON_PROTECTED => 5,
            PropertyType::X86_ISA => 6,
            PropertyType::X86_FEATURE => 7,
            PropertyType::NEEDED => 8,
        }
    }
}

/// Trait shared by all GNU property types
pub trait NoteProperty {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property;

    /// Return the type of the property
    fn property_type(&self) -> PropertyType {
        PropertyType::from(self.get_base().get_type())
    }
}

#[derive(Debug)]
/// Enum of the different GNU property subtypes
pub enum Properties<'a> {
    AArch64Feature(AArch64Feature<'a>),
    AArch64PAuth(AArch64PAuth<'a>),
    X86Features(X86Features<'a>),
    X86ISA(X86ISA<'a>),
    StackSize(StackSize<'a>),
    NoCopyOnProtected(NoCopyOnProtected<'a>),
    Needed(Needed<'a>),
    Generic(GenericProperty<'a>),
}

impl NoteProperty for Properties<'_> {
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property {
        match &self {
            Properties::AArch64Feature(p) => p.get_base(),
            Properties::AArch64PAuth(p) => p.get_base(),
            Properties::X86Features(p) => p.get_base(),
            Properties::X86ISA(p) => p.get_base(),
            Properties::StackSize(p) => p.get_base(),
            Properties::NoCopyOnProtected(p) => p.get_base(),
            Properties::Needed(p) => p.get_base(),
            Properties::Generic(p) => p.get_base(),
        }
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty_Property> for Properties<'_> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Property>) -> Self {
        unsafe {
            let prop_ref = ffi_entry.as_ref().unwrap();

            if ffi::ELF_NoteGnuProperty_AArch64Feature::classof(prop_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Property>;
                    type To = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_AArch64Feature>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Properties::AArch64Feature(AArch64Feature::from_ffi(raw))
            } else if ffi::ELF_NoteGnuProperty_AArch64PAuth::classof(prop_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Property>;
                    type To = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_AArch64PAuth>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Properties::AArch64PAuth(AArch64PAuth::from_ffi(raw))
            } else if ffi::ELF_NoteGnuProperty_X86Features::classof(prop_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Property>;
                    type To = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_X86Features>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Properties::X86Features(X86Features::from_ffi(raw))
            } else if ffi::ELF_NoteGnuProperty_X86ISA::classof(prop_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Property>;
                    type To = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_X86ISA>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Properties::X86ISA(X86ISA::from_ffi(raw))
            } else if ffi::ELF_NoteGnuProperty_StackSize::classof(prop_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Property>;
                    type To = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_StackSize>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Properties::StackSize(StackSize::from_ffi(raw))
            } else if ffi::ELF_NoteGnuProperty_NoteNoCopyOnProtected::classof(prop_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Property>;
                    type To = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_NoteNoCopyOnProtected>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Properties::NoCopyOnProtected(NoCopyOnProtected::from_ffi(raw))
            } else if ffi::ELF_NoteGnuProperty_Needed::classof(prop_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Property>;
                    type To = cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Needed>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Properties::Needed(Needed::from_ffi(raw))
            } else {
                assert!(ffi::ELF_NoteGnuProperty_Generic::classof(prop_ref));
                Properties::Generic(GenericProperty {
                    ptr: std::mem::transmute::<
                        cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Property>,
                        cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Generic>,
                    >(ffi_entry),
                    _owner: PhantomData,
                })
            }
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AArch64FeatureFlag {
    UNKNOWN,
    BTI,
    PAC,
}

impl From<u64> for AArch64FeatureFlag {
    fn from(value: u64) -> Self {
        match value {
            0 => AArch64FeatureFlag::UNKNOWN,
            1 => AArch64FeatureFlag::BTI,
            2 => AArch64FeatureFlag::PAC,
            _ => AArch64FeatureFlag::UNKNOWN,
        }
    }
}

/// AArch64 feature property (`GNU_PROPERTY_AARCH64_FEATURE_1_AND`)
pub struct AArch64Feature<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_AArch64Feature>,
    _owner: PhantomData<&'a ffi::ELF_NoteGnuProperty>,
}

impl AArch64Feature<'_> {
    /// Return the list of features
    pub fn features(&self) -> Vec<AArch64FeatureFlag> {
        Vec::from(self.ptr.features().as_slice())
            .into_iter()
            .map(AArch64FeatureFlag::from)
            .collect()
    }
}

impl NoteProperty for AArch64Feature<'_> {
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty_AArch64Feature> for AArch64Feature<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_AArch64Feature>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for AArch64Feature<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AArch64Feature")
            .field("type", &self.property_type())
            .field("features", &self.features())
            .finish()
    }
}

/// AArch64 pointer authentication property
pub struct AArch64PAuth<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_AArch64PAuth>,
    _owner: PhantomData<&'a ffi::ELF_NoteGnuProperty>,
}

impl AArch64PAuth<'_> {
    /// Platform identifier
    pub fn platform(&self) -> u64 {
        self.ptr.platform()
    }

    /// Version
    pub fn version(&self) -> u64 {
        self.ptr.version()
    }
}

impl NoteProperty for AArch64PAuth<'_> {
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty_AArch64PAuth> for AArch64PAuth<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_AArch64PAuth>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for AArch64PAuth<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AArch64PAuth")
            .field("type", &self.property_type())
            .field("platform", &self.platform())
            .field("version", &self.version())
            .finish()
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86FeatureFlag {
    NONE,
    USED,
    NEEDED,
    UNKNOWN(u64),
}

impl From<u64> for X86FeatureFlag {
    fn from(value: u64) -> Self {
        match value {
            0 => X86FeatureFlag::NONE,
            1 => X86FeatureFlag::USED,
            2 => X86FeatureFlag::NEEDED,
            _ => X86FeatureFlag::UNKNOWN(value),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86Feature {
    UNKNOWN,
    IBT,
    SHSTK,
    LAM_U48,
    LAM_U57,
    X86,
    X87,
    MMX,
    XMM,
    YMM,
    ZMM,
    FXSR,
    XSAVE,
    XSAVEOPT,
    XSAVEC,
    TMM,
    MASK,
}

impl From<u64> for X86Feature {
    fn from(value: u64) -> Self {
        match value {
            0 => X86Feature::UNKNOWN,
            1 => X86Feature::IBT,
            2 => X86Feature::SHSTK,
            3 => X86Feature::LAM_U48,
            4 => X86Feature::LAM_U57,
            5 => X86Feature::X86,
            6 => X86Feature::X87,
            7 => X86Feature::MMX,
            8 => X86Feature::XMM,
            9 => X86Feature::YMM,
            10 => X86Feature::ZMM,
            11 => X86Feature::FXSR,
            12 => X86Feature::XSAVE,
            13 => X86Feature::XSAVEOPT,
            14 => X86Feature::XSAVEC,
            15 => X86Feature::TMM,
            16 => X86Feature::MASK,
            _ => X86Feature::UNKNOWN,
        }
    }
}

/// X86 feature property (`GNU_PROPERTY_X86_FEATURE_*`)
pub struct X86Features<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_X86Features>,
    _owner: PhantomData<&'a ffi::ELF_NoteGnuProperty>,
}

impl X86Features<'_> {
    /// Return pairs of (flag, feature)
    pub fn features(&self) -> Vec<(X86FeatureFlag, X86Feature)> {
        self.ptr
            .features()
            .as_slice()
            .chunks_exact(2)
            .map(|c| (X86FeatureFlag::from(c[0]), X86Feature::from(c[1])))
            .collect()
    }
}

impl NoteProperty for X86Features<'_> {
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty_X86Features> for X86Features<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_X86Features>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for X86Features<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X86Features")
            .field("type", &self.property_type())
            .field("features", &self.features())
            .finish()
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86ISAFlag {
    NONE,
    USED,
    NEEDED,
    UNKNOWN(u64),
}

impl From<u64> for X86ISAFlag {
    fn from(value: u64) -> Self {
        match value {
            0 => X86ISAFlag::NONE,
            1 => X86ISAFlag::USED,
            2 => X86ISAFlag::NEEDED,
            _ => X86ISAFlag::UNKNOWN(value),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86ISAValue {
    UNKNOWN,
    BASELINE,
    V2,
    V3,
    V4,
    CMOV,
    FMA,
    I486,
    I586,
    I686,
    SSE,
    SSE2,
    SSE3,
    SSSE3,
    SSE4_1,
    SSE4_2,
    AVX,
    AVX2,
    AVX512F,
    AVX512CD,
    AVX512ER,
    AVX512PF,
    AVX512VL,
    AVX512DQ,
    AVX512BW,
    AVX512_4FMAPS,
    AVX512_4VNNIW,
    AVX512_BITALG,
    AVX512_IFMA,
    AVX512_VBMI,
    AVX512_VBMI2,
    AVX512_VNNI,
    AVX512_BF16,
}

impl From<u64> for X86ISAValue {
    fn from(value: u64) -> Self {
        match value {
            0 => X86ISAValue::UNKNOWN,
            1 => X86ISAValue::BASELINE,
            2 => X86ISAValue::V2,
            3 => X86ISAValue::V3,
            4 => X86ISAValue::V4,
            5 => X86ISAValue::CMOV,
            6 => X86ISAValue::FMA,
            7 => X86ISAValue::I486,
            8 => X86ISAValue::I586,
            9 => X86ISAValue::I686,
            10 => X86ISAValue::SSE,
            11 => X86ISAValue::SSE2,
            12 => X86ISAValue::SSE3,
            13 => X86ISAValue::SSSE3,
            14 => X86ISAValue::SSE4_1,
            15 => X86ISAValue::SSE4_2,
            16 => X86ISAValue::AVX,
            17 => X86ISAValue::AVX2,
            18 => X86ISAValue::AVX512F,
            19 => X86ISAValue::AVX512CD,
            20 => X86ISAValue::AVX512ER,
            21 => X86ISAValue::AVX512PF,
            22 => X86ISAValue::AVX512VL,
            23 => X86ISAValue::AVX512DQ,
            24 => X86ISAValue::AVX512BW,
            25 => X86ISAValue::AVX512_4FMAPS,
            26 => X86ISAValue::AVX512_4VNNIW,
            27 => X86ISAValue::AVX512_BITALG,
            28 => X86ISAValue::AVX512_IFMA,
            29 => X86ISAValue::AVX512_VBMI,
            30 => X86ISAValue::AVX512_VBMI2,
            31 => X86ISAValue::AVX512_VNNI,
            32 => X86ISAValue::AVX512_BF16,
            _ => X86ISAValue::UNKNOWN,
        }
    }
}

/// X86 ISA property (`GNU_PROPERTY_X86_ISA_1_*`)
pub struct X86ISA<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_X86ISA>,
    _owner: PhantomData<&'a ffi::ELF_NoteGnuProperty>,
}

impl X86ISA<'_> {
    /// Return pairs of (flag, isa)
    pub fn values(&self) -> Vec<(X86ISAFlag, X86ISAValue)> {
        self.ptr
            .values()
            .as_slice()
            .chunks_exact(2)
            .map(|c| (X86ISAFlag::from(c[0]), X86ISAValue::from(c[1])))
            .collect()
    }
}

impl NoteProperty for X86ISA<'_> {
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty_X86ISA> for X86ISA<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_X86ISA>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for X86ISA<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X86ISA")
            .field("type", &self.property_type())
            .field("values", &self.values())
            .finish()
    }
}

/// Stack size property (`GNU_PROPERTY_STACK_SIZE`)
pub struct StackSize<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_StackSize>,
    _owner: PhantomData<&'a ffi::ELF_NoteGnuProperty>,
}

impl StackSize<'_> {
    /// The stack size
    pub fn stack_size(&self) -> u64 {
        self.ptr.stack_size()
    }
}

impl NoteProperty for StackSize<'_> {
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty_StackSize> for StackSize<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_StackSize>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for StackSize<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StackSize")
            .field("type", &self.property_type())
            .field("stack_size", &self.stack_size())
            .finish()
    }
}

/// No copy on protected property (`GNU_PROPERTY_NO_COPY_ON_PROTECTED`)
pub struct NoCopyOnProtected<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_NoteNoCopyOnProtected>,
    _owner: PhantomData<&'a ffi::ELF_NoteGnuProperty>,
}

impl NoteProperty for NoCopyOnProtected<'_> {
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty_NoteNoCopyOnProtected> for NoCopyOnProtected<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_NoteNoCopyOnProtected>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for NoCopyOnProtected<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoCopyOnProtected")
            .field("type", &self.property_type())
            .finish()
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Flags for the `GNU_PROPERTY_1_NEEDED` property
pub enum NeedFlag {
    UNKNOWN,
    /// The object needs indirect external access
    INDIRECT_EXTERN_ACCESS,
}

impl From<u64> for NeedFlag {
    fn from(value: u64) -> Self {
        match value {
            0 => NeedFlag::UNKNOWN,
            1 => NeedFlag::INDIRECT_EXTERN_ACCESS,
            _ => NeedFlag::UNKNOWN,
        }
    }
}

/// Needed property (`GNU_PROPERTY_1_NEEDED`)
///
/// This property conveys information about additional features that the
/// object file needs at runtime (e.g. indirect external access).
pub struct Needed<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Needed>,
    _owner: PhantomData<&'a ffi::ELF_NoteGnuProperty>,
}

impl Needed<'_> {
    /// Return the list of needed features
    pub fn needs(&self) -> Vec<NeedFlag> {
        Vec::from(self.ptr.needs().as_slice())
            .into_iter()
            .map(NeedFlag::from)
            .collect()
    }
}

impl NoteProperty for Needed<'_> {
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty_Needed> for Needed<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Needed>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for Needed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Needed")
            .field("type", &self.property_type())
            .field("needs", &self.needs())
            .finish()
    }
}

/// Generic property (unrecognized by LIEF)
pub struct GenericProperty<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Generic>,
    _owner: PhantomData<&'a ffi::ELF_NoteGnuProperty>,
}

impl GenericProperty<'_> {
    /// The raw type value
    pub fn raw_type(&self) -> u32 {
        self.ptr.raw_type()
    }
}

impl NoteProperty for GenericProperty<'_> {
    fn get_base(&self) -> &ffi::ELF_NoteGnuProperty_Property {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty_Generic> for GenericProperty<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty_Generic>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for GenericProperty<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenericProperty")
            .field("type", &self.property_type())
            .field("raw_type", &self.raw_type())
            .finish()
    }
}
