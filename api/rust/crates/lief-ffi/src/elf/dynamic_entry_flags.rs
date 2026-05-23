#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/DynamicEntryFlags.hpp");

        type ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;

        type ELF_DynamicEntryFlags;

        #[Self = "ELF_DynamicEntryFlags"]
        fn classof(entry: &ELF_DynamicEntry) -> bool;
        #[Self = "ELF_DynamicEntryFlags"]
        fn create_dt_flag(value: u64) -> UniquePtr<ELF_DynamicEntryFlags>;
        #[Self = "ELF_DynamicEntryFlags"]
        fn create_dt_flag_1(value: u64) -> UniquePtr<ELF_DynamicEntryFlags>;
        fn flags(self: &ELF_DynamicEntryFlags) -> u64;
        fn add_flag(self: Pin<&mut ELF_DynamicEntryFlags>, f: u64);
        fn remove_flag(self: Pin<&mut ELF_DynamicEntryFlags>, f: u64);
    }
    impl UniquePtr<ELF_DynamicEntryFlags> {}
}
