use std::marker::PhantomData;

use super::commands::segment::Segment;
use super::section::Section;
use super::symbol::Symbol;
use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::generic;
use lief_ffi as ffi;

#[derive(Debug)]
pub enum Relocation<'a> {
    Generic(Generic<'a>),
    Dyld(Dyld<'a>),
    Fixup(Fixup<'a>),
    Object(Object<'a>),
}

impl<'a> FromFFI<ffi::MachO_Relocation> for Relocation<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::MachO_Relocation>) -> Self {
        unsafe {
            let cmd_ref = ffi_entry.as_ref().unwrap();

            if ffi::MachO_RelocationDyld::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Relocation>;
                    type To = cxx::UniquePtr<ffi::MachO_RelocationDyld>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Relocation::Dyld(Dyld::from_ffi(raw))
            } else if ffi::MachO_RelocationFixup::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Relocation>;
                    type To = cxx::UniquePtr<ffi::MachO_RelocationFixup>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Relocation::Fixup(Fixup::from_ffi(raw))
            } else if ffi::MachO_RelocationObject::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Relocation>;
                    type To = cxx::UniquePtr<ffi::MachO_RelocationObject>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Relocation::Object(Object::from_ffi(raw))
            } else {
                Relocation::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}

pub trait RelocationBase {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::MachO_Relocation;

    fn is_pc_relative(&self) -> bool {
        self.get_base().is_pc_relative()
    }

    fn symbol(&self) -> Option<Symbol> {
        into_optional(self.get_base().symbol())
    }

    fn section(&self) -> Option<Section> {
        into_optional(self.get_base().section())
    }

    fn segment(&self) -> Option<Segment> {
        into_optional(self.get_base().segment())
    }
}

impl std::fmt::Debug for &dyn RelocationBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Section")
            .field("is_pc_relative", &self.is_pc_relative())
            .field("symbol", &self.symbol())
            .field("section", &self.section())
            .field("segment", &self.segment())
            .finish()
    }
}

pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Relocation>,
    _owner: PhantomData<&'a ()>,
}

impl RelocationBase for Generic<'_> {
    fn get_base(&self) -> &ffi::MachO_Relocation {
        self.ptr.as_ref().unwrap()
    }
}

impl generic::Relocation for Generic<'_> {
    fn as_generic(&self) -> &ffi::AbstractRelocation {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Generic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn RelocationBase;
        f.debug_struct("Generic").field("base", &base).finish()
    }
}

impl FromFFI<ffi::MachO_Relocation> for Generic<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_Relocation>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub struct Dyld<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_RelocationDyld>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::MachO_RelocationDyld> for Dyld<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_RelocationDyld>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl RelocationBase for Dyld<'_> {
    fn get_base(&self) -> &ffi::MachO_Relocation {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Dyld<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn RelocationBase;
        f.debug_struct("Dyld").field("base", &base).finish()
    }
}

pub struct Fixup<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_RelocationFixup>,
    _owner: PhantomData<&'a ()>,
}

impl Fixup<'_> {
    pub fn target(&self) -> u64 {
        self.ptr.target()
    }
    pub fn ptr_format(&self) -> u32 {
        self.ptr.ptr_format()
    }
    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }
}

impl FromFFI<ffi::MachO_RelocationFixup> for Fixup<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_RelocationFixup>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl RelocationBase for Fixup<'_> {
    fn get_base(&self) -> &ffi::MachO_Relocation {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Fixup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn RelocationBase;
        f.debug_struct("Fixup")
            .field("base", &base)
            .field("target", &self.target())
            .field("ptr_format", &self.ptr_format())
            .field("offset", &self.offset())
            .finish()
    }
}

pub struct Object<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_RelocationObject>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::MachO_RelocationObject> for Object<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_RelocationObject>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl RelocationBase for Object<'_> {
    fn get_base(&self) -> &ffi::MachO_Relocation {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Object<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn RelocationBase;
        f.debug_struct("Object").field("base", &base).finish()
    }
}

declare_iterator!(
    Relocations,
    Relocation<'a>,
    ffi::MachO_Relocation,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_relocations
);
