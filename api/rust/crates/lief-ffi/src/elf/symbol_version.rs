#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/SymbolVersion.hpp");

        type ELF_SymbolVersionAux = crate::elf::symbol_version_aux::ffi::ELF_SymbolVersionAux;

        type ELF_SymbolVersion;

        fn value(self: &ELF_SymbolVersion) -> u16;
        fn symbol_version_auxiliary(self: &ELF_SymbolVersion) -> UniquePtr<ELF_SymbolVersionAux>;
        fn drop_version(self: Pin<&mut ELF_SymbolVersion>, value: u16);
        fn as_local(self: Pin<&mut ELF_SymbolVersion>);
        fn as_global(self: Pin<&mut ELF_SymbolVersion>);
    }

    impl UniquePtr<ELF_SymbolVersion> {}
}
