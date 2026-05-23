#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/DynamicEntry.hpp");

        type ELF_DynamicEntry;

        type LIEF_ELF_DynamicEntry;

        #[Self = "ELF_DynamicEntry"]
        fn create(tag: u64) -> UniquePtr<ELF_DynamicEntry>;
        fn tag(self: &ELF_DynamicEntry) -> u64;
        fn value(self: &ELF_DynamicEntry) -> u64;
        fn set_value(self: Pin<&mut ELF_DynamicEntry>, value: u64);
        fn to_string(self: &ELF_DynamicEntry) -> UniquePtr<CxxString>;
        fn raw_ptr(self: &ELF_DynamicEntry) -> *const LIEF_ELF_DynamicEntry;
    }
    impl UniquePtr<ELF_DynamicEntry> {}
}
