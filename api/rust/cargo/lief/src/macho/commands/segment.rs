use super::Command;
use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::to_slice;
use lief_ffi as ffi;
use std::marker::PhantomData;

use crate::macho::relocation::Relocation;
use crate::macho::section::Section;

use bitflags::bitflags;

bitflags! {
    /// Segment flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Flags: u64 {
        const HIGHVM = 0x1;
        const FVMLIB = 0x2;
        const NORELOC = 0x4;
        const PROTECTED_VERSION_1 = 0x8;
        const READ_ONLY = 0x10;
    }
}

impl From<u64> for Flags {
    fn from(value: u64) -> Self {
        Flags::from_bits_truncate(value)
    }
}
impl From<Flags> for u64 {
    fn from(value: Flags) -> Self {
        value.bits()
    }
}
impl std::fmt::Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

bitflags! {
    /// VM protection flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct VmProtections: u32 {
        const READ = 0x1;
        const WRITE = 0x2;
        const EXECUTE = 0x4;
    }
}

impl From<u32> for VmProtections {
    fn from(value: u32) -> Self {
        VmProtections::from_bits_truncate(value)
    }
}
impl From<VmProtections> for u32 {
    fn from(value: VmProtections) -> Self {
        value.bits()
    }
}
impl std::fmt::Display for VmProtections {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

/// Class which represents a `LC_SEGMENT/LC_SEGMENT_64` command
pub struct Segment<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_SegmentCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
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
    pub fn sections(&self) -> Sections<'_> {
        Sections::new(self.ptr.sections())
    }

    /// Return an iterator over the [`crate::macho::Relocation`] linked to this segment
    ///
    /// For Mach-O executable or library this iterator should be empty as
    /// the relocations are managed by the Dyld's rebase opcodes.
    /// On the other hand, for object files (`.o`) this iterator should not be empty.
    pub fn relocations(&self) -> Relocations<'_> {
        Relocations::new(self.ptr.relocations())
    }

    /// The original index of this segment or -1 if not defined
    pub fn index(&self) -> Option<u8> {
        let idx = self.ptr.index();
        if idx < 0 {
            None
        } else {
            Some(idx as u8)
        }
    }

    /// Return the [`Section`] with the given name (if any)
    pub fn get_section(&self, name: &str) -> Option<Section<'_>> {
        into_optional(self.ptr.get_section(name.to_string()))
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
            _owner: PhantomData,
        }
    }
}

impl Command for Segment<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(
    Segments,
    Segment<'a>,
    ffi::MachO_SegmentCommand,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_segments
);
declare_iterator!(
    Sections,
    Section<'a>,
    ffi::MachO_Section,
    ffi::MachO_SegmentCommand,
    ffi::MachO_SegmentCommand_it_sections
);
declare_iterator!(
    Relocations,
    Relocation<'a>,
    ffi::MachO_Relocation,
    ffi::MachO_SegmentCommand,
    ffi::MachO_SegmentCommand_it_relocations
);
