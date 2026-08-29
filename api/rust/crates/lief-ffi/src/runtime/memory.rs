#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/runtime/Memory.hpp");

        type runtime_Memory;
        type runtime_Memory_Chunk;

        fn addr(self: &runtime_Memory_Chunk) -> u64;
        fn size(self: &runtime_Memory_Chunk) -> u64;
        fn permissions(self: &runtime_Memory_Chunk) -> u32;
        fn page_start(self: &runtime_Memory_Chunk) -> u64;
        fn page_end(self: &runtime_Memory_Chunk) -> u64;
        fn change_permissions(self: Pin<&mut runtime_Memory_Chunk>, p: u32);
        fn make_x(self: Pin<&mut runtime_Memory_Chunk>);
        fn make_rw(self: Pin<&mut runtime_Memory_Chunk>);
        fn make_rx(self: Pin<&mut runtime_Memory_Chunk>);
        fn make_rwx(self: Pin<&mut runtime_Memory_Chunk>);
        fn make_ro(self: Pin<&mut runtime_Memory_Chunk>);
        fn cache_flush(self: Pin<&mut runtime_Memory_Chunk>);
        fn is_valid(self: &runtime_Memory_Chunk) -> bool;
        fn to_string(self: &runtime_Memory_Chunk) -> UniquePtr<CxxString>;

        #[Self = "runtime_Memory"]
        fn mmap(size: u64, flags: u32, permission: u32) -> UniquePtr<runtime_Memory_Chunk>;
        #[Self = "runtime_Memory"]
        fn mmap_hint(
            hint: u64,
            size: u64,
            flags: u32,
            permission: u32,
        ) -> UniquePtr<runtime_Memory_Chunk>;
        #[Self = "runtime_Memory"]
        fn munmap(chunk: Pin<&mut runtime_Memory_Chunk>, err: Pin<&mut u32>);
        #[Self = "runtime_Memory"]
        fn mprotect(chunk: Pin<&mut runtime_Memory_Chunk>, flags: u32, err: Pin<&mut u32>);
    }
    impl UniquePtr<runtime_Memory_Chunk> {}
}
