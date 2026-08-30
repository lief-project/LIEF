#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/MemoryLayout.hpp");

        type runtime_MemoryLayout_Region;
        type runtime_it_memory_layout;

        fn name(self: &runtime_MemoryLayout_Region) -> UniquePtr<CxxString>;
        fn addr(self: &runtime_MemoryLayout_Region) -> u64;
        fn size(self: &runtime_MemoryLayout_Region) -> u64;
        fn end_addr(self: &runtime_MemoryLayout_Region) -> u64;
        fn contains(self: &runtime_MemoryLayout_Region, addr: u64) -> bool;
        fn to_string(self: &runtime_MemoryLayout_Region) -> UniquePtr<CxxString>;

        fn next(self: Pin<&mut runtime_it_memory_layout>)
        -> UniquePtr<runtime_MemoryLayout_Region>;

        fn runtime_memory_layout() -> UniquePtr<runtime_it_memory_layout>;
    }
    impl UniquePtr<runtime_MemoryLayout_Region> {}
    impl UniquePtr<runtime_it_memory_layout> {}
}
