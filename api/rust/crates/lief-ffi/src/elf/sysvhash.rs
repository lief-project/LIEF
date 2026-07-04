#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/Sysvhash.hpp");

        type ELF_SysvHash;

        fn nbucket(self: &ELF_SysvHash) -> u32;
        fn nchain(self: &ELF_SysvHash) -> u32;
        fn buckets(self: &ELF_SysvHash) -> UniquePtr<CxxVector<u32>>;
        fn chains(self: &ELF_SysvHash) -> UniquePtr<CxxVector<u32>>;
    }

    impl UniquePtr<ELF_SysvHash> {}
}
