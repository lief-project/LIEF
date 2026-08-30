use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::declare_standalone_fwd_iterator;

/// A contiguous range of memory mapped in the current process.
pub struct Region {
    ptr: cxx::UniquePtr<ffi::runtime_MemoryLayout_Region>,
}

impl FromFFI<ffi::runtime_MemoryLayout_Region> for Region {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::runtime_MemoryLayout_Region>) -> Self {
        Self { ptr }
    }
}

impl Region {
    /// Name associated with the region: name/path of the module mapped at this
    /// address (e.g. `libc.so.6`) or the identifier of a region that is not
    /// backed by a file (e.g. `[stack]`, `[heap]`).
    ///
    /// It can be empty for anonymous regions.
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Address at which the region starts
    pub fn addr(&self) -> u64 {
        self.ptr.addr()
    }

    /// Size of the region
    pub fn size(&self) -> u64 {
        self.ptr.size()
    }

    /// Address at which the region ends
    pub fn end_addr(&self) -> u64 {
        self.ptr.end_addr()
    }

    /// Whether the given address is within this region
    pub fn contains(&self, addr: u64) -> bool {
        self.ptr.contains(addr)
    }
}

impl std::fmt::Display for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

impl std::fmt::Debug for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Region")
            .field("name", &self.name())
            .field("addr", &self.addr())
            .field("size", &self.size())
            .field("end_addr", &self.end_addr())
            .finish()
    }
}

/// Return an iterator over the memory layout of the current process
pub fn memory_layout() -> RegionsIt {
    RegionsIt::new(ffi::runtime_memory_layout())
}

declare_standalone_fwd_iterator!(
    RegionsIt,
    Region,
    ffi::runtime_MemoryLayout_Region,
    ffi::runtime_it_memory_layout
);
