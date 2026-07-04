#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/GnuHash.hpp");

        type ELF_GnuHash;

        fn nb_buckets(self: &ELF_GnuHash) -> u32;
        fn symbol_index(self: &ELF_GnuHash) -> u32;
        fn shift2(self: &ELF_GnuHash) -> u32;
        fn maskwords(self: &ELF_GnuHash) -> u32;
        fn bloom_filters(self: &ELF_GnuHash) -> UniquePtr<CxxVector<u64>>;
        fn buckets(self: &ELF_GnuHash) -> UniquePtr<CxxVector<u32>>;
        fn hash_values(self: &ELF_GnuHash) -> UniquePtr<CxxVector<u32>>;
    }

    impl UniquePtr<ELF_GnuHash> {}
}
