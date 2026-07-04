#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/DynamicEntryArray.hpp");

        type ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;

        type ELF_DynamicEntryArray;

        #[Self = "ELF_DynamicEntryArray"]
        fn classof(entry: &ELF_DynamicEntry) -> bool;
        fn array(self: &ELF_DynamicEntryArray) -> UniquePtr<CxxVector<u64>>;
    }
    impl UniquePtr<ELF_DynamicEntryArray> {}
}
