//! Module that contains COFF-related structure used by the PE format

use std::marker::PhantomData;
use crate::common::FromFFI;

use lief_ffi as ffi;

pub struct String<'a> {
    ptr: cxx::UniquePtr<ffi::PE_COFFString>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl<'a> FromFFI<ffi::PE_COFFString> for String<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_COFFString>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// This class represents a string located in the COFF string table.
///
/// Some of these strings can be used for section names that are greater than 8
/// bytes. See: [`crate::pe::Section::coff_string`]
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-string-table>
impl String<'_> {
    /// The actual string
    pub fn str(&self) -> std::string::String {
        self.ptr.str().to_string()
    }

    /// The offset of this string the in the COFF string table.
    /// This offset includes the first 4-bytes that holds the table size
    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }
}
