#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/COFF/Binary.hpp");
        include!("LIEF/rust/COFF/Section.hpp");
        include!("LIEF/rust/COFF/Relocation.hpp");

        type COFF_Header = crate::coff::header::ffi::COFF_Header;
        type COFF_Relocation = crate::coff::relocation::ffi::COFF_Relocation;
        type COFF_Section = crate::coff::section::ffi::COFF_Section;
        type COFF_String = crate::coff::string::ffi::COFF_String;
        type COFF_Symbol = crate::coff::symbol::ffi::COFF_Symbol;
        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;

        type COFF_Binary;

        #[Self = "COFF_Binary"]
        fn parse(path: &CxxString) -> UniquePtr<COFF_Binary>;
        fn header(self: &COFF_Binary) -> UniquePtr<COFF_Header>;
        fn sections(self: &COFF_Binary) -> UniquePtr<COFF_Binary_it_sections>;
        fn symbols(self: &COFF_Binary) -> UniquePtr<COFF_Binary_it_symbols>;
        fn relocations(self: &COFF_Binary) -> UniquePtr<COFF_Binary_it_relocations>;
        fn string_table(self: &COFF_Binary) -> UniquePtr<COFF_Binary_it_strings>;
        fn find_string(self: &COFF_Binary, offset: u32) -> UniquePtr<COFF_String>;
        fn find_function(self: &COFF_Binary, name: &CxxString) -> UniquePtr<COFF_Symbol>;
        fn find_demangled_function(self: &COFF_Binary, name: &CxxString) -> UniquePtr<COFF_Symbol>;
        fn functions(self: &COFF_Binary) -> UniquePtr<COFF_Binary_it_functions>;
        fn disassemble_function(
            self: &COFF_Binary,
            function: &CxxString,
        ) -> UniquePtr<COFF_Binary_it_instructions>;
        fn to_string(self: &COFF_Binary) -> UniquePtr<CxxString>;
        fn disassemble_symbol(
            self: &COFF_Binary,
            sym: &COFF_Symbol,
        ) -> UniquePtr<COFF_Binary_it_instructions>;
        unsafe fn disassemble_buffer(
            self: &COFF_Binary,
            ptr: *const u8,
            size: u64,
            addr: u64,
        ) -> UniquePtr<COFF_Binary_it_instructions>;

        type COFF_Binary_it_functions;

        fn next(self: Pin<&mut COFF_Binary_it_functions>) -> UniquePtr<COFF_Symbol>;
        fn size(self: &COFF_Binary_it_functions) -> u64;

        type COFF_Binary_it_instructions;

        fn next(self: Pin<&mut COFF_Binary_it_instructions>) -> UniquePtr<asm_Instruction>;

        type COFF_Binary_it_relocations;

        fn next(self: Pin<&mut COFF_Binary_it_relocations>) -> UniquePtr<COFF_Relocation>;
        fn size(self: &COFF_Binary_it_relocations) -> u64;

        type COFF_Binary_it_sections;

        fn next(self: Pin<&mut COFF_Binary_it_sections>) -> UniquePtr<COFF_Section>;
        fn size(self: &COFF_Binary_it_sections) -> u64;

        type COFF_Binary_it_strings;

        fn next(self: Pin<&mut COFF_Binary_it_strings>) -> UniquePtr<COFF_String>;
        fn size(self: &COFF_Binary_it_strings) -> u64;

        type COFF_Binary_it_symbols;

        fn next(self: Pin<&mut COFF_Binary_it_symbols>) -> UniquePtr<COFF_Symbol>;
        fn size(self: &COFF_Binary_it_symbols) -> u64;
    }
    impl UniquePtr<COFF_Binary> {}
    impl UniquePtr<COFF_Binary_it_functions> {}
    impl UniquePtr<COFF_Binary_it_instructions> {}
    impl UniquePtr<COFF_Binary_it_relocations> {}
    impl UniquePtr<COFF_Binary_it_sections> {}
    impl UniquePtr<COFF_Binary_it_strings> {}
    impl UniquePtr<COFF_Binary_it_symbols> {}
}
