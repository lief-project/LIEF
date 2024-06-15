use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;
use crate::to_slice;

use std::marker::PhantomData;

/// Structure that represents the `LC_SEGMENT_SPLIT_INFO` command
pub struct SegmentSplitInfo<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_SegmentSplitInfo>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl SegmentSplitInfo<'_> {
    pub fn data_offset(&self) -> u32 {
        self.ptr.data_offset()
    }
    pub fn data_size(&self) -> u32 {
        self.ptr.data_size()
    }
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
}

impl std::fmt::Debug for SegmentSplitInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("SegmentSplitInfo")
            .field("base", &base)
            .field("data_offset", &self.data_offset())
            .field("data_size", &self.data_size())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_SegmentSplitInfo> for SegmentSplitInfo<'a> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_SegmentSplitInfo>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for SegmentSplitInfo<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

