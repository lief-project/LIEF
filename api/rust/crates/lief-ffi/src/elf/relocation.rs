#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/Relocation.hpp");

        type ELF_Section = crate::elf::section::ffi::ELF_Section;
        type ELF_Symbol = crate::elf::symbol::ffi::ELF_Symbol;

        type ELF_Relocation;

        fn addend(self: &ELF_Relocation) -> i64;
        fn get_type(self: &ELF_Relocation) -> u32;
        fn is_rela(self: &ELF_Relocation) -> bool;
        fn is_rel(self: &ELF_Relocation) -> bool;
        fn info(self: &ELF_Relocation) -> u32;
        fn architecture(self: &ELF_Relocation) -> u32;
        fn purpose(self: &ELF_Relocation) -> u32;
        fn encoding(self: &ELF_Relocation) -> u32;
        fn symbol(self: &ELF_Relocation) -> UniquePtr<ELF_Symbol>;
        fn section(self: &ELF_Relocation) -> UniquePtr<ELF_Section>;
        fn symbol_table(self: &ELF_Relocation) -> UniquePtr<ELF_Section>;
        fn resolve(self: &ELF_Relocation, base_address: u64, err: Pin<&mut u32>) -> u64;
    }

    impl UniquePtr<ELF_Relocation> {}
}
