use super::Command;
use lief_ffi as ffi;

use crate::to_slice;
use crate::{common::FromFFI, declare_iterator};
use std::marker::PhantomData;

pub struct DataInCode<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_DataInCode>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl DataInCode<'_> {
    pub fn data_offset(&self) -> u32 {
        self.ptr.data_offset()
    }
    pub fn data_size(&self) -> u32 {
        self.ptr.data_size()
    }
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
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
pub enum ENTRY_TYPE {
    DATA,
    JUMP_TABLE_8,
    JUMP_TABLE_16,
    JUMP_TABLE_32,
    ABS_JUMP_TABLE_32,
    UNKNOWN(u32),
}

impl ENTRY_TYPE {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000001 => ENTRY_TYPE::DATA,
            0x00000002 => ENTRY_TYPE::JUMP_TABLE_8,
            0x00000003 => ENTRY_TYPE::JUMP_TABLE_16,
            0x00000004 => ENTRY_TYPE::JUMP_TABLE_32,
            0x00000005 => ENTRY_TYPE::ABS_JUMP_TABLE_32,
            _ => ENTRY_TYPE::UNKNOWN(value),
        }
    }
}

impl DataCodeEntry<'_> {
    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }
    pub fn length(&self) -> u32 {
        self.ptr.length()
    }
    pub fn get_type(&self) -> ENTRY_TYPE {
        ENTRY_TYPE::from_value(self.ptr.get_type())
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
