//! Module that wraps the different debug information structure we can find in a PE binary.

use std::marker::PhantomData;

use crate::declare_iterator;
use crate::{common::FromFFI, to_slice};
use lief_ffi as ffi;

#[derive(Debug)]
/// This enum exposes the different debug entries that can be
/// found in the debug DataDirectory.
pub enum Entries<'a> {
    CodeView(CodeView<'a>),
    /// Entry associated with the `IMAGE_DEBUG_TYPE_CODEVIEW`
    CodeViewPDB(CodeViewPDB<'a>),
    /// Entry associated with `IMAGE_DEBUG_TYPE_REPRO`
    Repro(Repro<'a>),
    /// Entry associated with `IMAGE_DEBUG_TYPE_POGO`
    Pogo(Pogo<'a>),
    /// Generic entry for all the other ``IMAGE_DEBUG_xxx`
    Generic(Generic<'a>),
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum Type {
    COFF,
    CODEVIEW,
    FPO,
    MISC,
    EXCEPTION,
    FIXUP,
    OMAP_TO_SRC,
    OMAP_FROM_SRC,
    BORLAND,
    RESERVED10,
    CLSID,
    VC_FEATURE,
    POGO,
    ILTCG,
    MPX,
    REPRO,
    EX_DLLCHARACTERISTICS,
    UNKNOWN(u32),
}

impl From<u32> for Type {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Type::COFF,
            0x00000002 => Type::CODEVIEW,
            0x00000003 => Type::FPO,
            0x00000004 => Type::MISC,
            0x00000005 => Type::EXCEPTION,
            0x00000006 => Type::FIXUP,
            0x00000007 => Type::OMAP_TO_SRC,
            0x00000008 => Type::OMAP_FROM_SRC,
            0x00000009 => Type::BORLAND,
            0x0000000a => Type::RESERVED10,
            0x0000000b => Type::CLSID,
            0x0000000c => Type::VC_FEATURE,
            0x0000000d => Type::POGO,
            0x0000000e => Type::ILTCG,
            0x0000000f => Type::MPX,
            0x00000010 => Type::REPRO,
            0x00000014 => Type::EX_DLLCHARACTERISTICS,
            _ => Type::UNKNOWN(value),
        }
    }
}

pub trait DebugEntry {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::PE_Debug;

    /// Reserved should be 0
    fn characteristics(&self) -> u32 {
        self.get_base().characteristics()
    }

    /// The time and date when the debug data was created.
    fn timestamp(&self) -> u32 {
        self.get_base().timestamp()
    }

    /// The major version number of the debug data format.
    fn major_version(&self) -> u16 {
        self.get_base().major_version()
    }

    /// The minor version number of the debug data format.
    fn minor_version(&self) -> u16 {
        self.get_base().minor_version()
    }

    /// The format of the debugging information
    fn get_type(&self) -> Type {
        Type::from(self.get_base().get_type())
    }

    /// Size of the debug data
    fn sizeof_data(&self) -> u32 {
        self.get_base().sizeof_data()
    }

    /// Address of the debug data relative to the image base
    fn addressof_rawdata(&self) -> u32 {
        self.get_base().addressof_rawdata()
    }

    /// File offset of the debug data
    fn pointerto_rawdata(&self) -> u32 {
        self.get_base().pointerto_rawdata()
    }
}

impl DebugEntry for Entries<'_> {
    fn get_base(&self) -> &ffi::PE_Debug {
        match &self {
            Entries::CodeView(entry) => {
                entry.get_base()
            }

            Entries::CodeViewPDB(entry) => {
                entry.get_base()
            }

            Entries::Repro(entry) => {
                entry.get_base()
            }

            Entries::Pogo(entry) => {
                entry.get_base()
            }

            Entries::Generic(entry) => {
                entry.get_base()
            }
        }
    }
}

impl std::fmt::Debug for &dyn DebugEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebugEntry")
            .field("characteristics", &self.characteristics())
            .field("timestamp", &self.timestamp())
            .field("major_version", &self.major_version())
            .field("minor_version", &self.minor_version())
            .field("type", &self.get_type())
            .field("sizeof_data", &self.sizeof_data())
            .field("addressof_rawdata", &self.addressof_rawdata())
            .field("pointerto_rawdata", &self.pointerto_rawdata())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_Debug> for Entries<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_Debug>) -> Self {
        unsafe {
            let debug_ref = ffi_entry.as_ref().unwrap();
            if ffi::PE_Pogo::classof(debug_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Debug>;
                    type To = cxx::UniquePtr<ffi::PE_Pogo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Pogo(Pogo::from_ffi(raw))
            } else if ffi::PE_CodeViewPDB::classof(debug_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Debug>;
                    type To = cxx::UniquePtr<ffi::PE_CodeViewPDB>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::CodeViewPDB(CodeViewPDB::from_ffi(raw))
            } else if ffi::PE_Repro::classof(debug_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Debug>;
                    type To = cxx::UniquePtr<ffi::PE_Repro>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::Repro(Repro::from_ffi(raw))
            } else if ffi::PE_CodeView::classof(debug_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Debug>;
                    type To = cxx::UniquePtr<ffi::PE_CodeView>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Entries::CodeView(CodeView::from_ffi(raw))
            } else {
                Entries::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}

pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Debug>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl<'a> FromFFI<ffi::PE_Debug> for Generic<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Debug>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DebugEntry for Generic<'_> {
    fn get_base(&self) -> &ffi::PE_Debug {
        self.ptr.as_ref().unwrap()
    }
}

impl std::fmt::Debug for Generic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn DebugEntry;
        f.debug_struct("Generic").field("base", &base).finish()
    }
}

/// This structure represents a *Profile Guided Optimization* entry from the
/// debug directory (`IMAGE_DEBUG_TYPE_POGO`).
pub struct Pogo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Pogo>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl Pogo<'_> {

    /// An iterator over the different POGO elements: [`PogoEntry`]
    pub fn entries(&self) -> PogoEntries {
        PogoEntries::new(self.ptr.entries())
    }
}

impl<'a> FromFFI<ffi::PE_Pogo> for Pogo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Pogo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DebugEntry for Pogo<'_> {
    fn get_base(&self) -> &ffi::PE_Debug {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Pogo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn DebugEntry;
        f.debug_struct("Pogo").field("base", &base).finish()
    }
}

/// Structure which reprents an entry in the [`Pogo`] debug structure
pub struct PogoEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_PogoEntry>,
    _owner: PhantomData<&'a ffi::PE_Pogo>,
}

impl<'a> FromFFI<ffi::PE_PogoEntry> for PogoEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_PogoEntry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl PogoEntry<'_> {
    pub fn start_rva(&self) -> u32 {
        self.ptr.start_rva()
    }
    pub fn size(&self) -> u32 {
        self.ptr.size()
    }
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }
}

impl std::fmt::Debug for PogoEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PogoEntry")
            .field("name", &self.name())
            .field("size", &self.size())
            .field("start_rva", &self.start_rva())
            .finish()
    }
}

/// Structure that represents the (generic) Debug CodeView (`IMAGE_DEBUG_TYPE_CODEVIEW`).
pub struct CodeView<'a> {
    ptr: cxx::UniquePtr<ffi::PE_CodeView>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl<'a> FromFFI<ffi::PE_CodeView> for CodeView<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_CodeView>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DebugEntry for CodeView<'_> {
    fn get_base(&self) -> &ffi::PE_Debug {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for CodeView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeView").finish()
    }
}

/// CodeView PDB specialization
pub struct CodeViewPDB<'a> {
    ptr: cxx::UniquePtr<ffi::PE_CodeViewPDB>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl<'a> FromFFI<ffi::PE_CodeViewPDB> for CodeViewPDB<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_CodeViewPDB>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// CodeView PDB specialization
impl CodeViewPDB<'_> {
    /// Age value to verify. The age does not necessarily correspond to any known
    /// time value, it is used to determine if a .pdb file is out of sync with a corresponding
    /// `.exe` file.
    pub fn age(&self) -> u32 {
        self.ptr.age()
    }

    /// The path to the `.pdb` file
    pub fn filename(&self) -> String {
        self.ptr.filename().to_string()
    }

    /// The GUID signature to verify against the .pdb file signature.
    /// This attribute might be used to lookup remote PDB file on a symbol server.
    pub fn guid(&self) -> String {
        self.ptr.guid().to_string()
    }

    /// The 32-bit signature to verify against the .pdb file signature.
    pub fn signature(&self) -> [u8; 16] {
        let vector: Vec<u8> = self.ptr.signature().iter().map(|&e| e as u8).collect();
        vector.try_into().expect("Wrong size")
    }

}

impl DebugEntry for CodeViewPDB<'_> {
    fn get_base(&self) -> &ffi::PE_Debug {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl std::fmt::Debug for CodeViewPDB<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn DebugEntry;
        f.debug_struct("CodeViewPDB")
            .field("base", &base)
            .field("age", &self.age())
            .field("filename", &self.filename())
            .finish()
    }
}

/// This structure represents a reproducible build entry from the debug directory
/// (`IMAGE_DEBUG_TYPE_REPRO`)
///
/// This entry is usually generated with the undocumented `/Brepro` linker flag.
/// See: <https://nikhilism.com/post/2020/windows-deterministic-builds/>
pub struct Repro<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Repro>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl<'a> FromFFI<ffi::PE_Repro> for Repro<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Repro>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Repro<'_> {
    /// The hash associated with the reproducible build
    pub fn hash(&self) -> &[u8] {
        to_slice!(self.ptr.hash());
    }
}

impl DebugEntry for Repro<'_> {
    fn get_base(&self) -> &ffi::PE_Debug {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Repro<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn DebugEntry;
        f.debug_struct("Repro").field("base", &base).finish()
    }
}

declare_iterator!(
    PogoEntries,
    PogoEntry<'a>,
    ffi::PE_PogoEntry,
    ffi::PE_Pogo,
    ffi::PE_Pogo_it_entries
);
