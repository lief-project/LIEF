use super::Command;
use lief_ffi as ffi;
use crate::common::FromFFI;
use crate::declare_iterator;
use std::marker::PhantomData;
use crate::to_slice;

use crate::macho::section::Section;
use crate::macho::relocation::Relocation;

/// Class which represents a `LC_SEGMENT/LC_SEGMENT_64` command
pub struct Segment<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_SegmentCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}

impl Segment<'_> {
    /// Name of the segment (e.g. `__TEXT`)
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Absolute virtual base address of the segment
    pub fn virtual_address(&self) -> u64 {
        self.ptr.virtual_address()
    }

    /// Virtual size of the segment
    pub fn virtual_size(&self) -> u64 {
        self.ptr.virtual_size()
    }

    /// Size of this segment in the binary file
    pub fn file_size(&self) -> u64 {
        self.ptr.file_size()
    }

    /// Offset of the data of this segment in the file
    pub fn file_offset(&self) -> u64 {
        self.ptr.file_offset()
    }

    /// The maximum of protections for this segment
    pub fn max_protection(&self) -> u32 {
        self.ptr.max_protection()
    }

    /// The initial protections of this segment
    pub fn init_protection(&self) -> u32 {
        self.ptr.init_protection()
    }

    /// The number of sections associated with this segment
    pub fn numberof_sections(&self) -> u32 {
        self.ptr.numberof_sections()
    }

    /// Flags associated with this segment
    pub fn flags(&self) -> u32 {
        self.ptr.flags()
    }

    /// The raw content of this segment as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }

    /// Iterator over the [`crate::macho::Section`] owned by this segment
    pub fn sections(&self) -> Sections {
        Sections::new(self.ptr.sections())
    }

    /// Return an iterator over the [`crate::macho::Relocation`] linked to this segment
    ///
    /// For Mach-O executable or library this iterator should be empty as
    /// the relocations are managed by the Dyld's rebase opcodes.
    /// On the other hand, for object files (`.o`) this iterator should not be empty.
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
