#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/DynamicSharedObject.hpp");

        type ELF_DynamicEntry = crate::elf::dynamic_entry::ffi::ELF_DynamicEntry;

        type ELF_DynamicSharedObject;

        #[Self = "ELF_DynamicSharedObject"]
        fn create(name: &CxxString) -> UniquePtr<ELF_DynamicSharedObject>;
        #[Self = "ELF_DynamicSharedObject"]
        fn classof(entry: &ELF_DynamicEntry) -> bool;
        fn name(self: &ELF_DynamicSharedObject) -> UniquePtr<CxxString>;
        fn set_name(self: Pin<&mut ELF_DynamicSharedObject>, name: &CxxString);
    }
    impl UniquePtr<ELF_DynamicSharedObject> {}
}
