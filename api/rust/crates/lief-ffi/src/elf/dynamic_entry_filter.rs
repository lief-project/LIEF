#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/DynamicEntryFilter.hpp");

        type ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;

        type ELF_DynamicEntryFilter;

        #[Self = "ELF_DynamicEntryFilter"]
        fn create(name: &CxxString) -> UniquePtr<ELF_DynamicEntryFilter>;
        #[Self = "ELF_DynamicEntryFilter"]
        fn classof(entry: &ELF_DynamicEntry) -> bool;
        fn name(self: &ELF_DynamicEntryFilter) -> UniquePtr<CxxString>;
        fn set_name(self: Pin<&mut ELF_DynamicEntryFilter>, name: &CxxString);
    }
    impl UniquePtr<ELF_DynamicEntryFilter> {}
}
