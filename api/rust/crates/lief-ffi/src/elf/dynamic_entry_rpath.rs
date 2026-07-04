#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/DynamicEntryRpath.hpp");

        type ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;

        type ELF_DynamicEntryRpath;

        #[Self = "ELF_DynamicEntryRpath"]
        fn create(name: &CxxString) -> UniquePtr<ELF_DynamicEntryRpath>;
        #[Self = "ELF_DynamicEntryRpath"]
        fn classof(entry: &ELF_DynamicEntry) -> bool;
        fn rpath(self: &ELF_DynamicEntryRpath) -> UniquePtr<CxxString>;
        fn paths(self: &ELF_DynamicEntryRpath) -> UniquePtr<CxxVector<CxxString>>;
        fn insert(self: Pin<&mut ELF_DynamicEntryRpath>, pos: u32, name: &CxxString);
        fn append(self: Pin<&mut ELF_DynamicEntryRpath>, name: &CxxString);
        fn remove(self: Pin<&mut ELF_DynamicEntryRpath>, path: &CxxString);
        fn set_rpath(self: Pin<&mut ELF_DynamicEntryRpath>, path: &CxxString);
    }
    impl UniquePtr<ELF_DynamicEntryRpath> {}
}
