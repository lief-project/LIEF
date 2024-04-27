use lief_ffi as ffi;
use std::fmt;
use std::marker::PhantomData;
use crate::common::{FromFFI, into_optional};

pub struct SymbolVersion<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_SymbolVersion>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl SymbolVersion<'_> {
    pub fn value(&self) -> u16 {
        self.ptr.value()
    }

    pub fn symbol_version_auxiliary(&self) -> Option<SymbolVersionAux> {
        into_optional(self.ptr.symbol_version_auxiliary())
    }
}

impl fmt::Debug for SymbolVersion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolVersion")
            .field("value", &self.value())
            .field("symbol_version_auxiliary", &self.symbol_version_auxiliary())
            .finish()
    }
}

impl FromFFI<ffi::ELF_SymbolVersion> for SymbolVersion<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_SymbolVersion>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

pub struct SymbolVersionAux<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionAux>,
    _owner: PhantomData<&'a ()>
}


impl SymbolVersionAux<'_> {
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }
}

impl fmt::Debug for SymbolVersionAux<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolVersionAux")
            .field("name", &self.name())
            .finish()
    }
}

impl FromFFI<ffi::ELF_SymbolVersionAux> for SymbolVersionAux<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionAux>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

pub struct SymbolVersionAuxRequirement<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionAuxRequirement>,
    _owner: PhantomData<&'a ()>
}


impl SymbolVersionAuxRequirement<'_> {
    pub fn hash(&self) -> u32 {
        self.ptr.hash()
    }
    pub fn flags(&self) -> u16 {
        self.ptr.flags()
    }
    pub fn other(&self) -> u16 {
        self.ptr.other()
    }

}

impl fmt::Debug for SymbolVersionAuxRequirement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolVersionAuxRequirement")
            .field("hash", &self.hash())
            .field("flags", &self.flags())
            .field("other", &self.other())
            .finish()
    }
}

impl FromFFI<ffi::ELF_SymbolVersionAuxRequirement> for SymbolVersionAuxRequirement<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionAuxRequirement>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

pub struct SymbolVersionDefinition<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionDefinition>,
    _owner: PhantomData<&'a ()>
}


impl SymbolVersionDefinition<'_> {
    pub fn version(&self) -> u16 {
        self.ptr.version()
    }
    pub fn flags(&self) -> u16 {
        self.ptr.flags()
    }
    pub fn ndx(&self) -> u16 {
        self.ptr.ndx()
    }
    pub fn hash(&self) -> u32 {
        self.ptr.hash()
    }
}

impl fmt::Debug for SymbolVersionDefinition<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolVersionDefinition")
            .field("version", &self.version())
            .field("flags", &self.flags())
            .field("ndx", &self.ndx())
            .field("hash", &self.hash())
            .finish()
    }
}

impl FromFFI<ffi::ELF_SymbolVersionDefinition> for SymbolVersionDefinition<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionDefinition>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

pub struct SymbolVersionRequirement<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionRequirement>,
    _owner: PhantomData<&'a ()>
}

impl SymbolVersionRequirement<'_> {
    pub fn version(&self) -> u16 {
        self.ptr.version()
    }
    pub fn cnt(&self) -> u32 {
        self.ptr.cnt()
    }
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }
}

impl fmt::Debug for SymbolVersionRequirement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolVersionRequirement")
            .field("verison", &self.version())
            .field("cnt", &self.cnt())
            .field("name", &self.name())
            .finish()
    }
}

impl FromFFI<ffi::ELF_SymbolVersionRequirement> for SymbolVersionRequirement<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionRequirement>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

