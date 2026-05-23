#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/CorePrPsInfo.hpp");

        type ELF_Note = crate::elf::note::ffi::ELF_Note;

        type ELF_CorePrPsInfo;

        #[Self = "ELF_CorePrPsInfo"]
        fn classof(note: &ELF_Note) -> bool;
    }
    impl UniquePtr<ELF_CorePrPsInfo> {}
}
