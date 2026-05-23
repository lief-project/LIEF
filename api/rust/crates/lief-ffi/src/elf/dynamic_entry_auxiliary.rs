#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/DynamicEntryAuxiliary.hpp");

        type ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;

        type ELF_DynamicEntryAuxiliary;

        #[Self = "ELF_DynamicEntryAuxiliary"]
        fn create(name: &CxxString) -> UniquePtr<ELF_DynamicEntryAuxiliary>;
        #[Self = "ELF_DynamicEntryAuxiliary"]
        fn classof(entry: &ELF_DynamicEntry) -> bool;
        fn name(self: &ELF_DynamicEntryAuxiliary) -> UniquePtr<CxxString>;
        fn set_name(self: Pin<&mut ELF_DynamicEntryAuxiliary>, name: &CxxString);
    }
    impl UniquePtr<ELF_DynamicEntryAuxiliary> {}
}
