#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/Symbol.hpp");

        type ELF_Section = crate::elf::section::ffi::ELF_Section;
        type ELF_SymbolVersion = crate::elf::symbol_version::ffi::ELF_SymbolVersion;

        type ELF_Symbol;

        fn get_type(self: &ELF_Symbol) -> u32;
        fn binding(self: &ELF_Symbol) -> u32;
        fn information(self: &ELF_Symbol) -> u8;
        fn other(self: &ELF_Symbol) -> u8;
        fn section_idx(self: &ELF_Symbol) -> u16;
        fn visibility(self: &ELF_Symbol) -> u32;
        fn section(self: &ELF_Symbol) -> UniquePtr<ELF_Section>;
        fn symbol_version(self: &ELF_Symbol) -> UniquePtr<ELF_SymbolVersion>;
        fn demangled_name(self: &ELF_Symbol) -> UniquePtr<CxxString>;
        fn to_string(self: &ELF_Symbol) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<ELF_Symbol> {}
}
