use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;

use crate::dwarf::Type;

/// This class represents a `DW_TAG_array_type`
pub struct Array<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Array>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Array> for Array<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_Array>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Array<'_> {
    /// The underlying type of this array
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }

    /// Return information about the size of this array.
    ///
    /// This size info is usually embedded in a `DW_TAG_subrange_type` DIE which
    /// is represented by the [`SizeInfo`] structure.
    pub fn size_info(&self) -> SizeInfo {
        SizeInfo::from_ffi(self.ptr.size_info())
    }
}

impl DwarfType for Array<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

/// Structure that wraps information about the dimension of this array
pub struct SizeInfo<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_array_size_info>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_array_size_info> for SizeInfo<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_array_size_info>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl SizeInfo<'_> {
    /// Name of the index (usually not relevant like `__ARRAY_SIZE_TYPE__`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Size of the array. For instance in `uint8_t[3]`, it returns 3
    pub fn size(&self) -> u64 {
        self.ptr.size()
    }

    /// Type of the **index** for this array.
    ///
    /// For instance in `uint8_t[3]` the index type could be set to a `size_t`.
    pub fn get_type(&self) -> Option<Type> {
        into_optional(self.ptr.get_type())
    }
}
