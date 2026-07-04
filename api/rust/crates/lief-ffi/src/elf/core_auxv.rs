#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/CoreAuxv.hpp");

        type ELF_Note = crate::elf::note::ffi::ELF_Note;

        type ELF_CoreAuxv;

        #[Self = "ELF_CoreAuxv"]
        fn classof(note: &ELF_Note) -> bool;
        fn values(self: &ELF_CoreAuxv) -> UniquePtr<CxxVector<u64>>;
    }
    impl UniquePtr<ELF_CoreAuxv> {}
}
