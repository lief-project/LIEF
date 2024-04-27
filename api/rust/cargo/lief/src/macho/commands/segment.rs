use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;
use crate::declare_iterator;
use std::marker::PhantomData;
use crate::to_slice;

use crate::macho::section::Section;
use crate::macho::relocation::Relocation;

pub struct Segment<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_SegmentCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl Segment<'_> {
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }
    pub fn virtual_address(&self) -> u64 {
        self.ptr.virtual_address()
    }
    pub fn virtual_size(&self) -> u64 {
        self.ptr.virtual_size()
    }
    pub fn file_size(&self) -> u64 {
        self.ptr.file_size()
    }
    pub fn file_offset(&self) -> u64 {
        self.ptr.file_offset()
    }
    pub fn max_protection(&self) -> u32 {
        self.ptr.max_protection()
    }
    pub fn init_protection(&self) -> u32 {
        self.ptr.init_protection()
    }
    pub fn numberof_sections(&self) -> u32 {
        self.ptr.numberof_sections()
    }
    pub fn flags(&self) -> u32 {
        self.ptr.flags()
    }
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
    pub fn sections(&self) -> Sections {
        Sections::new(self.ptr.sections())
    }
    pub fn relocations(&self) -> Relocations {
        Relocations::new(self.ptr.relocations())
    }
}

impl std::fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("Segment")
            .field("base", &base)
            .field("name", &self.name())
            .field("virtual_address", &self.virtual_address())
            .field("virtual_size", &self.virtual_size())
            .field("file_size", &self.file_size())
            .field("file_offset", &self.file_offset())
            .field("max_protection", &self.max_protection())
            .field("init_protection", &self.init_protection())
            .field("numberof_sections", &self.numberof_sections())
            .field("flags", &self.flags())
            .finish()
    }
}

impl FromFFI<ffi::MachO_SegmentCommand> for Segment<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_SegmentCommand>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for Segment<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(Segments, Segment<'a>, ffi::MachO_SegmentCommand, ffi::MachO_Binary, ffi::MachO_Binary_it_segments);
declare_iterator!(Sections, Section<'a>, ffi::MachO_Section, ffi::MachO_SegmentCommand, ffi::MachO_SegmentCommand_it_sections);
declare_iterator!(Relocations, Relocation<'a>, ffi::MachO_Relocation, ffi::MachO_SegmentCommand, ffi::MachO_SegmentCommand_it_relocations);
