use lief_ffi as ffi;
use bitflags::bitflags;
use std::fmt;
use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::{declare_iterator, to_slice};

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    /// Unused segment
    PT_NULL,
    /// Loadable segment
    LOAD,
    /// Dynamic linking information.
    DYNAMIC,
    /// Interpreter pathname.
    INTERP,
    /// Auxiliary information.
    NOTE,
    /// Reserved
    SHLIB,
    /// The program header table itself.
    PHDR,
    /// The thread-local storage template.
    TLS,
    GNU_EH_FRAME,
    /// Indicates stack executability
    GNU_STACK,
    /// GNU property
    GNU_PROPERTY,
    /// Read-only after relocation.
    GNU_RELRO,
    /// Platform architecture compatibility info
    ARM_ARCHEXT,
    ARM_EXIDX,
    ARM_UNWIND,
    AARCH64_MEMTAG_MTE,
    /// Register usage information
    MIPS_REGINFO,
    /// Runtime procedure table.
    MIPS_RTPROC,
    /// Options segment.
    MIPS_OPTIONS,
    /// Abiflags segment.
    MIPS_ABIFLAGS,
    RISCV_ATTRIBUTES,
    UNKNOWN(u64),
}

impl Type {
    pub fn from_value(value: u64) -> Self {
        match value {
            0x00000000 => Type::PT_NULL,
            0x00000001 => Type::LOAD,
            0x00000002 => Type::DYNAMIC,
            0x00000003 => Type::INTERP,
            0x00000004 => Type::NOTE,
            0x00000005 => Type::SHLIB,
            0x00000006 => Type::PHDR,
            0x00000007 => Type::TLS,
            0x6474e550 => Type::GNU_EH_FRAME,
            0x6474e551 => Type::GNU_STACK,
            0x6474e553 => Type::GNU_PROPERTY,
            0x6474e552 => Type::GNU_RELRO,
            0x270000000 => Type::ARM_ARCHEXT,
            0x270000001 => Type::ARM_EXIDX,
            0x470000002 => Type::AARCH64_MEMTAG_MTE,
            0x670000000 => Type::MIPS_REGINFO,
            0x670000001 => Type::MIPS_RTPROC,
            0x670000002 => Type::MIPS_OPTIONS,
            0x670000003 => Type::MIPS_ABIFLAGS,
            0x870000003 => Type::RISCV_ATTRIBUTES,
            _ => Type::UNKNOWN(value),

        }
    }
}



bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Flags: u32 {
        const NONE = 0x0;
        const X = 0x1;
        const W = 0x2;
        const R = 0x4;
    }
}


impl Flags {
    pub fn from_value(value: u32) -> Self {
        Flags::from_bits_truncate(value)
    }
}

/// Structure which reprents an ELF segment
pub struct Segment<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_Segment>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Segment")
            .field("p_type", &self.p_type())
            .field("flags", &self.flags())
            .field("file_offset", &self.file_offset())
            .field("virtual_address", &self.virtual_address())
            .field("physical_address", &self.physical_address())
            .field("physical_size", &self.physical_size())
            .field("virtual_size", &self.virtual_size())
            .field("alignment", &self.alignment())
            .finish()
    }
}

impl FromFFI<ffi::ELF_Segment> for Segment<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_Segment>) -> Self {
        Segment {
            ptr,
            _owner: PhantomData
        }
    }
}

impl<'a> Segment<'a> {
    /// Content of the segment as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }

    /// The segment's type (LOAD, DYNAMIC, ...)
    pub fn p_type(&self) -> Type {
        Type::from_value(self.ptr.stype())
    }

    /// The flag permissions associated with this segment
    pub fn flags(&self) -> u32 {
        self.ptr.flags()
    }

    /// The file offset of the data associated with this segment
    pub fn file_offset(&self) -> u64 {
        self.ptr.file_offset()
    }

    /// The virtual address of the segment.
    pub fn virtual_address(&self) -> u64 {
        self.ptr.virtual_address()
    }
    /// The physical address of the segment.
    /// This value is not really relevant on systems like Linux or Android.
    /// On the other hand, Qualcomm trustlets might use this value.
    ///
    /// Usually this value matches [`Segment::virtual_address`]
    pub fn physical_address(&self) -> u64 {
        self.ptr.physical_address()
    }

    /// The **file** size of the data associated with this segment
    pub fn physical_size(&self) -> u64 {
        self.ptr.physical_size()
    }

    /// The in-memory size of this segment.
    /// Usually, if the `.bss` segment is wrapped by this segment
    /// then, virtual_size is larger than physical_size
    pub fn virtual_size(&self) -> u64 {
        self.ptr.virtual_size()
    }

    /// The offset alignment of the segment
    pub fn alignment(&self) -> u64 {
        self.ptr.alignment()
    }
}

impl fmt::Display for Segment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

declare_iterator!(Segments, Segment<'a>, ffi::ELF_Segment, ffi::ELF_Binary, ffi::ELF_Binary_it_segments);
