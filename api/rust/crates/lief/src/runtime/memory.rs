use crate::to_ok_result;
use bitflags::bitflags;

use lief_ffi as ffi;
use num_traits::{Num, cast};

use crate::{
    Error,
    common::{FromFFI, into_optional},
};

bitflags! {
    /// Flags used when creating a memory map (mmap).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MmapFlags: u32 {
        const NONE = 0;
        /// Changes are private to this process (copy-on-write).
        const PRIVATE = 1 << 0;

        /// The mapping is not backed by any file.
        const ANONYMOUS = 1 << 1;

        /// Changes are shared.
        const SHARED = 1 << 2;

        /// Interpret the address as a fixed requirement.
        const FIXED = 1 << 3;

        /// Map for Just-In-Time code generation.
        const JIT = 1 << 4;
    }
}

impl std::fmt::Display for MmapFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl From<u32> for MmapFlags {
    fn from(value: u32) -> Self {
        MmapFlags::from_bits_truncate(value)
    }
}

impl From<MmapFlags> for u32 {
    fn from(value: MmapFlags) -> Self {
        value.bits()
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Perm: u32 {
        const NONE = 0;
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC = 1 << 2;
    }
}

impl std::fmt::Display for Perm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl From<u32> for Perm {
    fn from(value: u32) -> Self {
        Perm::from_bits_truncate(value)
    }
}

impl From<Perm> for u32 {
    fn from(value: Perm) -> Self {
        value.bits()
    }
}

/// Represents a contiguous chunk of memory allocated or inspected by the runtime.
pub struct Chunk {
    ptr: cxx::UniquePtr<ffi::runtime_Memory_Chunk>,
}

impl FromFFI<ffi::runtime_Memory_Chunk> for Chunk {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::runtime_Memory_Chunk>) -> Self {
        Self { ptr }
    }
}

impl Chunk {
    /// Returns the start address of the memory chunk.
    pub fn addr(&self) -> u64 {
        self.ptr.addr()
    }

    /// Returns the size of the memory chunk in bytes.
    pub fn size(&self) -> u64 {
        self.ptr.size()
    }

    /// Returns the current permissions of the memory chunk.
    pub fn permissions(&self) -> Perm {
        Perm::from(self.ptr.permissions())
    }

    /// Returns the address of the start of the page containing this chunk.
    pub fn page_start(&self) -> u64 {
        self.ptr.page_start()
    }

    /// Returns the address of the end of the page containing this chunk.
    pub fn page_end(&self) -> u64 {
        self.ptr.page_end()
    }

    /// Changes the permissions of the memory chunk.
    pub fn change_permissions(&mut self, perm: Perm) {
        self.ptr.pin_mut().change_permissions(perm.into());
    }

    /// Sets the permissions to Execute only.
    pub fn make_x(&mut self) {
        self.ptr.pin_mut().make_x();
    }

    /// Sets the permissions to Read and Write.
    pub fn make_rw(&mut self) {
        self.ptr.pin_mut().make_rw();
    }

    /// Sets the permissions to Read and Execute.
    pub fn make_rx(&mut self) {
        self.ptr.pin_mut().make_rx();
    }

    /// Sets the permissions to Read, Write, and Execute.
    pub fn make_rwx(&mut self) {
        self.ptr.pin_mut().make_rwx();
    }

    /// Sets the permissions to Read Only.
    pub fn make_ro(&mut self) {
        self.ptr.pin_mut().make_ro();
    }

    /// Flushes the instruction cache for this memory chunk.
    /// This should be used when modifying code in memory (e.g., hooking, JIT).
    pub fn cache_flush(&mut self) {
        self.ptr.pin_mut().cache_flush();
    }

    pub fn is_valid(&self) -> bool {
        self.ptr.is_valid()
    }
}

impl std::fmt::Display for Chunk {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

pub struct Memory {}

impl Memory {
    /// Allocates a memory chunk through mmap-like function
    pub fn mmap(size: u64, flags: MmapFlags, permission: Perm) -> Option<Chunk> {
        into_optional(ffi::runtime_Memory::mmap(
            size,
            flags.into(),
            permission.into(),
        ))
    }

    /// Allocate a memory chunk through mmap-like function and
    /// place the allocation at or near the address given in the first parameter.
    ///
    /// This address is a **hint**: it is rounded up to the next page boundary
    /// (next allocation granularity on Windows) and the system remains free to
    /// return a chunk located somewhere else.
    pub fn mmap_hint(hint: u64, size: u64, flags: MmapFlags, permission: Perm) -> Option<Chunk> {
        into_optional(ffi::runtime_Memory::mmap_hint(
            hint,
            size,
            flags.into(),
            permission.into(),
        ))
    }

    /// Deallocates a mmaped memory chunk
    pub fn munmap(chunk: &mut Chunk) -> Result<(), Error> {
        to_ok_result!(ffi::runtime_Memory::munmap, chunk.ptr.pin_mut());
    }

    /// Sets the permission of the given memory chunk
    pub fn mprotect(chunk: &mut Chunk, perm: Perm) -> Result<(), Error> {
        to_ok_result!(
            ffi::runtime_Memory::mprotect,
            chunk.ptr.pin_mut(),
            perm.into()
        );
    }

    /// Reads a value of type `T` from a raw memory address.
    ///
    /// # Safety
    /// This function is unsafe and the caller must ensure that the operation is valid
    pub unsafe fn read<T>(addr: u64) -> T
    where
        T: Num + cast::FromPrimitive + cast::ToPrimitive + Clone,
    {
        let ptr = addr as *const T;
        unsafe { (*ptr).clone() }
    }

    /// Writes a value of type `T` to a raw memory address.
    ///
    /// # Safety
    /// This function is unsafe and the caller must ensure that the operation is valid
    pub unsafe fn write<T>(addr: u64, value: T)
    where
        T: Num + cast::FromPrimitive + cast::ToPrimitive,
    {
        let ptr = addr as *mut T;
        unsafe {
            *ptr = value;
        }
    }
}
