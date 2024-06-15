//! This module represents the PE's Thread Local Storage (TLS)

use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use crate::to_slice;
use std::marker::PhantomData;

use crate::pe::Section;
use crate::pe::DataDirectory;

pub struct TLS<'a> {
    ptr: cxx::UniquePtr<ffi::PE_TLS>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for TLS<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TLS")
            .field("callbacks", &self.callbacks())
            .field("addressof_index", &self.addressof_index())
            .field("addressof_callbacks", &self.addressof_callbacks())
            .field("sizeof_zero_fill", &self.sizeof_zero_fill())
            .field("characteristics", &self.characteristics())
            .finish()
    }
}

impl TLS<'_> {
    /// List of callbacks associated with the current TLS
    ///
    /// These functions are called before any other functions.
    pub fn callbacks(&self) -> Vec<u64> {
        Vec::from(self.ptr.callbacks().as_slice())
    }
    /// The location to receive the TLS index assigned by the loader
    pub fn addressof_index(&self) -> u64 {
        self.ptr.addressof_index()
    }

    /// Pointer to an array of TLS callback functions.
    ///
    /// The array is null-terminated, so if there is no callback function this field points to 4
    /// bytes set to zero.
    ///
    /// See [`TLS::callbacks`]
    pub fn addressof_callbacks(&self) -> u64 {
        self.ptr.addressof_callbacks()
    }

    /// Size in bytes of the zero to be *padded* after the data specified by [`TLS::data_template`]
    pub fn sizeof_zero_fill(&self) -> u64 {
        self.ptr.sizeof_zero_fill()
    }

    /// The four bits `[23:20]` describe alignment info.
    ///
    /// Possible values are those defined as `IMAGE_SCN_ALIGN_*`, which are also used to describe
    /// alignment of section in object files.
    ///
    /// The other 28 bits are reserved for future use.
    pub fn characteristics(&self) -> u64 {
        self.ptr.characteristics()
    }

    /// The initial content used to initialize TLS data.
    pub fn data_template(&self) -> &[u8] {
        to_slice!(self.ptr.data_template());
    }

    /// Range of addresses where the [`TLS::data_template`] is located.
    pub fn addressof_raw_data(&self) -> (u64, u64) {
        let vec = Vec::from(self.ptr.addressof_raw_data().as_slice());
        if vec.len() != 2 {
            return (0, 0);
        }
        (vec[0], vec[1])
    }

    /// The section where the TLS structure is located
    pub fn section(&self) -> Option<Section> {
        into_optional(self.ptr.section())
    }

    /// The data directory describing the TLS
    pub fn directory(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.data_directory())
    }
}

impl<'a> FromFFI<ffi::PE_TLS> for TLS<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_TLS>) -> Self {
        TLS {
            ptr,
            _owner: PhantomData,
        }
    }
}
