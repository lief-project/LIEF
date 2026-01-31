use lief_ffi as ffi;
use std::fmt;
use crate::declare_iterator;
use std::marker::PhantomData;
use crate::common::{FromFFI, into_optional};

/// Structure which represents an entry defined in the `DT_VERSYM`
/// dynamic entry
pub struct SymbolVersion<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_SymbolVersion>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl SymbolVersion<'_> {
    /// Value associated with the symbol
    ///
    /// If the given [`SymbolVersion`] doesn't have [`SymbolVersion::symbol_version_auxiliary`]:
    ///
    /// * `0` means **Local**
    /// * `1` means **Global**
    pub fn value(&self) -> u16 {
        self.ptr.value()
    }

    /// SymbolVersionAux associated with the current Version if any.
    pub fn symbol_version_auxiliary(&self) -> Option<SymbolVersionAux<'_>> {
        into_optional(self.ptr.symbol_version_auxiliary())
    }

    /// Drop the versioning requirement and replace the value (local/global)
    pub fn drop_version(&mut self, value: u16) {
        self.ptr.pin_mut().drop_version(value)
    }

    /// Redefine this version as local by dropping its auxiliary version
    ///
    /// See: [`SymbolVersion::as_global`], [`SymbolVersion::drop_version`]
    pub fn as_local(&mut self) {
        self.ptr.pin_mut().as_local()
    }

    /// Redefine this version as global by dropping its auxiliary version
    ///
    /// See: [`SymbolVersion::as_local`], [`SymbolVersion::drop_version`]
    pub fn as_global(&mut self) {
        self.ptr.pin_mut().as_global()
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
    /// Hash value of the dependency name (use ELF hashing function)
    pub fn hash(&self) -> u32 {
        self.ptr.hash()
    }
    /// Bitmask of flags
    pub fn flags(&self) -> u16 {
        self.ptr.flags()
    }

    /// It returns the unique version index for the file which is used in the
    /// version symbol table. If the highest bit (bit 15) is set this
    /// is a hidden symbol which cannot be referenced from outside the
    /// object.
    pub fn other(&self) -> u16 {
        self.ptr.other()
    }


    /// Symbol's aux name (e.g. `GLIBC_2.2.5`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
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

/// Structure which represents an entry defined in `DT_VERDEF` or `.gnu.version_d`
pub struct SymbolVersionDefinition<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionDefinition>,
    _owner: PhantomData<&'a ()>
}


impl SymbolVersionDefinition<'_> {
    /// Version revision
    ///
    /// This field should always have the value `1`. It will be changed
    /// if the versioning implementation has to be changed in an incompatible way.
    pub fn version(&self) -> u16 {
        self.ptr.version()
    }

    /// Version information
    pub fn flags(&self) -> u16 {
        self.ptr.flags()
    }

    /// Version index
    /// Numeric value used as an index in the [`SymbolVersion`] table
    pub fn ndx(&self) -> u16 {
        self.ptr.ndx()
    }

    /// Hash value of the symbol's name (using ELF hash function)
    pub fn hash(&self) -> u32 {
        self.ptr.hash()
    }

    /// Iterator over the [`SymbolVersionAux`] associated with this entry
    pub fn auxiliary_symbols(&self) -> DefAuxiliarySymbols<'_> {
        DefAuxiliarySymbols::new(self.ptr.sym_aux())
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


/// Structure which represents an entry in the `DT_VERNEED` or `.gnu.version_r` table
pub struct SymbolVersionRequirement<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_SymbolVersionRequirement>,
    _owner: PhantomData<&'a ()>
}

impl SymbolVersionRequirement<'_> {
    /// Version revision
    ///
    /// This field should always have the value `1`. It will be changed
    /// if the versioning implementation has to be changed in an incompatible way.
    pub fn version(&self) -> u16 {
        self.ptr.version()
    }

    /// Number of auxiliary entries
    pub fn cnt(&self) -> u32 {
        self.ptr.cnt()
    }

    /// Return the library name associated with this requirement (e.g. `libc.so.6`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Auxiliary entries as an iterator over [`SymbolVersionAuxRequirement`]
    pub fn auxiliary_symbols(&self) -> AuxiliarySymbols<'_> {
        AuxiliarySymbols::new(self.ptr.auxiliary_symbols())
    }

    pub fn set_name(&mut self, name: &str) {
        self.ptr.pin_mut().set_name(name.to_string());
    }

    pub fn set_version(&mut self, version: u16) {
        self.ptr.pin_mut().set_version(version);
    }

    /// Try to find the [`SymbolVersionAuxRequirement`] with the given name (e.g. `GLIBC_2.27`)
    pub fn find_aux(&self, name: &str) -> Option<SymbolVersionAuxRequirement<'_>> {
        into_optional(self.ptr.find_aux(name.to_string()))
    }


    /// Try to remove the auxiliary requirement symbol with the given name.
    /// The function returns true if the operation succeed, false otherwise.
    ///
    /// **warning**:
    ///
    /// This function invalidates all the references of
    /// [`SymbolVersionAuxRequirement`]. Therefore, the user is reponsible
    /// to ensure that the auxiliary requirement is no longer used in the
    /// ELF binary (e.g. in [`SymbolVersion`])
    pub fn remove_aux_requirement_by_name(&mut self, name: &str) -> bool {
        self.ptr.pin_mut().remove_aux_requirement_by_name(name.to_string())
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

declare_iterator!(
    AuxiliarySymbols,
    SymbolVersionAuxRequirement<'a>,
    ffi::ELF_SymbolVersionAuxRequirement,
    ffi::ELF_SymbolVersionRequirement,
    ffi::ELF_SymbolVersionRequirement_it_auxiliary_symbols
);
declare_iterator!(
    DefAuxiliarySymbols,
    SymbolVersionAux<'a>,
    ffi::ELF_SymbolVersionAux,
    ffi::ELF_SymbolVersionDefinition,
    ffi::ELF_SymbolVersionDefinition_it_auxiliary_symbols
);

