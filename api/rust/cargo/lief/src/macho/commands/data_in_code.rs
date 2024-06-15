use super::Command;
use lief_ffi as ffi;

use crate::to_slice;
use crate::{common::FromFFI, declare_iterator};
use std::marker::PhantomData;

/// Structure that represents the `LC_DATA_IN_CODE` command
///
/// This command is used to list slices of code sections that contain data. The *slices*
/// information are stored as an array of [`DataCodeEntry`]
pub struct DataInCode<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_DataInCode>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl DataInCode<'_> {
    /// Start of the array of the [`DataCodeEntry`] entries
    pub fn data_offset(&self) -> u32 {
        self.ptr.data_offset()
    }

    /// Size of the (raw) array (`size = sizeof(DataCodeEntry) * nb_elements`)
    pub fn data_size(&self) -> u32 {
        self.ptr.data_size()
    }

    /// Raw content as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }

    /// Iterator over the [`DataCodeEntry`]
    pub fn entries(&self) -> Entries {
        Entries::new(self.ptr.entries())
    }
}

impl std::fmt::Debug for DataInCode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("DataInCode")
            .field("base", &base)
            .field("data_offset", &self.data_offset())
            .field("data_size", &self.data_size())
            .finish()
    }
}

impl FromFFI<ffi::MachO_DataInCode> for DataInCode<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_DataInCode>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for DataInCode<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

pub struct DataCodeEntry<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_DataCodeEntry>,
    _owner: PhantomData<&'a ffi::MachO_DataInCode>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum EntryType {
    DATA,
    JUMP_TABLE_8,
    JUMP_TABLE_16,
    JUMP_TABLE_32,
    ABS_JUMP_TABLE_32,
    UNKNOWN(u32),
}

impl From<u32> for EntryType {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => EntryType::DATA,
            0x00000002 => EntryType::JUMP_TABLE_8,
            0x00000003 => EntryType::JUMP_TABLE_16,
            0x00000004 => EntryType::JUMP_TABLE_32,
            0x00000005 => EntryType::ABS_JUMP_TABLE_32,
            _ => EntryType::UNKNOWN(value),
        }
    }
}

impl DataCodeEntry<'_> {
    /// Offset of the data
    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }
    /// Length of the data
    pub fn length(&self) -> u32 {
        self.ptr.length()
    }

    /// Type of the data
    pub fn get_type(&self) -> EntryType {
        EntryType::from(self.ptr.get_type())
    }
}

impl std::fmt::Debug for DataCodeEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataCodeEntry")
            .field("offset", &self.offset())
            .field("length", &self.length())
            .field("type", &self.get_type())
            .finish()
    }
}

impl FromFFI<ffi::MachO_DataCodeEntry> for DataCodeEntry<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_DataCodeEntry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

declare_iterator!(
    Entries,
    DataCodeEntry<'a>,
    ffi::MachO_DataCodeEntry,
    ffi::MachO_DataInCode,
    ffi::MachO_DataInCode_it_entries
);
