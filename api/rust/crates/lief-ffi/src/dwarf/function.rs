#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/Function.hpp");

        type Range = crate::utils::ffi::Range;
        type DWARF_LexicalBlock = crate::dwarf::lexical_block::ffi::DWARF_LexicalBlock;
        type DWARF_Parameter = crate::dwarf::parameter::ffi::DWARF_Parameter;
        type DWARF_Scope = crate::dwarf::scope::ffi::DWARF_Scope;
        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;
        type DWARF_Variable = crate::dwarf::variable::ffi::DWARF_Variable;
        type DebugLocation = crate::debug_location::ffi::DebugLocation;
        type LIEF_DeclOpt = crate::debug_decl_opt::ffi::LIEF_DeclOpt;
        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;

        type DWARF_Function;

        fn ranges(self: &DWARF_Function) -> UniquePtr<CxxVector<Range>>;
        fn name(self: &DWARF_Function) -> UniquePtr<CxxString>;
        fn linkage_name(self: &DWARF_Function) -> UniquePtr<CxxString>;
        fn variables(self: &DWARF_Function) -> UniquePtr<DWARF_Function_it_variables>;
        fn address(self: &DWARF_Function, err: Pin<&mut u32>) -> u64;
        fn is_artificial(self: &DWARF_Function) -> bool;
        fn is_external(self: &DWARF_Function) -> bool;
        fn size(self: &DWARF_Function) -> u64;
        fn debug_location(self: &DWARF_Function) -> UniquePtr<DebugLocation>;
        fn get_type(self: &DWARF_Function) -> UniquePtr<DWARF_Type>;
        fn parameters(self: &DWARF_Function) -> UniquePtr<DWARF_Function_it_parameters>;
        fn thrown_types(self: &DWARF_Function) -> UniquePtr<DWARF_Function_it_thrown_types>;
        fn scope(self: &DWARF_Function) -> UniquePtr<DWARF_Scope>;
        fn instructions(self: &DWARF_Function) -> UniquePtr<DWARF_Function_it_instructions>;
        fn description(self: &DWARF_Function) -> UniquePtr<CxxString>;
        fn lexical_blocks(self: &DWARF_Function) -> UniquePtr<DWARF_Function_it_lexical_blocks>;
        fn to_decl(self: &DWARF_Function) -> UniquePtr<CxxString>;
        fn to_decl_with_opt(self: &DWARF_Function, opt: &LIEF_DeclOpt) -> UniquePtr<CxxString>;

        type DWARF_Function_it_instructions;

        fn next(self: Pin<&mut DWARF_Function_it_instructions>) -> UniquePtr<asm_Instruction>;

        type DWARF_Function_it_lexical_blocks;

        fn next(self: Pin<&mut DWARF_Function_it_lexical_blocks>) -> UniquePtr<DWARF_LexicalBlock>;
        fn size(self: &DWARF_Function_it_lexical_blocks) -> u64;

        type DWARF_Function_it_parameters;

        fn next(self: Pin<&mut DWARF_Function_it_parameters>) -> UniquePtr<DWARF_Parameter>;
        fn size(self: &DWARF_Function_it_parameters) -> u64;

        type DWARF_Function_it_thrown_types;

        fn next(self: Pin<&mut DWARF_Function_it_thrown_types>) -> UniquePtr<DWARF_Type>;
        fn size(self: &DWARF_Function_it_thrown_types) -> u64;

        type DWARF_Function_it_variables;

        fn next(self: Pin<&mut DWARF_Function_it_variables>) -> UniquePtr<DWARF_Variable>;
        fn size(self: &DWARF_Function_it_variables) -> u64;
    }

    impl UniquePtr<DWARF_Function> {}
    impl UniquePtr<DWARF_Function_it_instructions> {}
    impl UniquePtr<DWARF_Function_it_lexical_blocks> {}
    impl UniquePtr<DWARF_Function_it_parameters> {}
    impl UniquePtr<DWARF_Function_it_thrown_types> {}
    impl UniquePtr<DWARF_Function_it_variables> {}
}
