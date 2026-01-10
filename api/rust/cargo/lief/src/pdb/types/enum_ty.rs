use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use std::marker::PhantomData;
use crate::pdb::types::{PdbType, Type};

use crate::declare_fwd_iterator;

/// This structure wraps a `LF_ENUM` PDB type
pub struct Enum<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Enum>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Enum> for Enum<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Enum>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Enum<'_> {
    /// Entries associated with this enum
    pub fn entries(&self) -> Entries<'_> {
        Entries::new(self.ptr.entries())
    }

    /// The underlying type that is used to encode this enum
    pub fn underlying_type(&self) -> Option<Type<'_>> {
        into_optional(self.ptr.underlying_type())
    }

    /// Try to find the enum entry matching the given value
    pub fn entry_by_value(&self, value: i64) -> Option<Entry<'_>> {
        into_optional(self.ptr.find_entry(value))
    }
}

impl PdbType for Enum<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

/// This struct represents an enum entry which is essentially composed of a name and its value
/// (integer).
pub struct Entry<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Enum_Entry>,
    _owner: PhantomData<&'a ()>,
}

impl Entry<'_> {
    /// Enum entry's name
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Enum entry's value
    pub fn value(&self) -> i64 {
        self.ptr.value()
    }
}


impl FromFFI<ffi::PDB_types_Enum_Entry> for Entry<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Enum_Entry>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

declare_fwd_iterator!(
    Entries,
    Entry<'a>,
    ffi::PDB_types_Enum_Entry,
    ffi::PDB_types_Enum,
    ffi::PDB_types_Enum_it_entries
);
