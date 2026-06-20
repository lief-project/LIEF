#[repr(C)]
pub struct Language {
    pub lang: u32,
    pub version: u32,
}

unsafe impl cxx::ExternType for Language {
    type Id = cxx::type_id!("DWARF_CompilationUnit_Language");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/CompilationUnit.hpp");

        type Range = crate::utils::ffi::Range;
        type DWARF_Function = crate::dwarf::function::ffi::DWARF_Function;
        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;
        type DWARF_Variable = crate::dwarf::variable::ffi::DWARF_Variable;
        type DWARF_CompilationUnit_Language = crate::dwarf::compilation_unit::Language;
        type LIEF_DeclOpt = crate::debug_decl_opt::ffi::LIEF_DeclOpt;

        type DWARF_CompilationUnit;

        fn ranges(self: &DWARF_CompilationUnit) -> UniquePtr<CxxVector<Range>>;
        fn language(self: &DWARF_CompilationUnit) -> DWARF_CompilationUnit_Language;

        fn name(self: &DWARF_CompilationUnit) -> UniquePtr<CxxString>;
        fn producer(self: &DWARF_CompilationUnit) -> UniquePtr<CxxString>;
        fn compilation_dir(self: &DWARF_CompilationUnit) -> UniquePtr<CxxString>;
        fn low_address(self: &DWARF_CompilationUnit) -> u64;
        fn high_address(self: &DWARF_CompilationUnit) -> u64;
        fn size(self: &DWARF_CompilationUnit) -> u64;
        fn function_by_name(
            self: &DWARF_CompilationUnit,
            name: &CxxString,
        ) -> UniquePtr<DWARF_Function>;
        fn variable_by_name(
            self: &DWARF_CompilationUnit,
            name: &CxxString,
        ) -> UniquePtr<DWARF_Variable>;
        fn functions(self: &DWARF_CompilationUnit)
            -> UniquePtr<DWARF_CompilationUnit_it_functions>;
        fn imported_functions(
            self: &DWARF_CompilationUnit,
        ) -> UniquePtr<DWARF_CompilationUnit_it_functions>;
        fn types(self: &DWARF_CompilationUnit) -> UniquePtr<DWARF_CompilationUnit_it_types>;
        fn variables(self: &DWARF_CompilationUnit)
            -> UniquePtr<DWARF_CompilationUnit_it_variables>;
        fn function_by_address(
            self: &DWARF_CompilationUnit,
            addr: u64,
        ) -> UniquePtr<DWARF_Function>;
        fn variable_by_address(
            self: &DWARF_CompilationUnit,
            addr: u64,
        ) -> UniquePtr<DWARF_Variable>;
        fn to_decl(self: &DWARF_CompilationUnit) -> UniquePtr<CxxString>;
        fn to_decl_with_opt(
            self: &DWARF_CompilationUnit,
            opt: &LIEF_DeclOpt,
        ) -> UniquePtr<CxxString>;

        type DWARF_CompilationUnit_it_functions;

        fn next(self: Pin<&mut DWARF_CompilationUnit_it_functions>) -> UniquePtr<DWARF_Function>;
        fn size(self: &DWARF_CompilationUnit_it_functions) -> u64;

        type DWARF_CompilationUnit_it_types;

        fn next(self: Pin<&mut DWARF_CompilationUnit_it_types>) -> UniquePtr<DWARF_Type>;
        fn size(self: &DWARF_CompilationUnit_it_types) -> u64;

        type DWARF_CompilationUnit_it_variables;

        fn next(self: Pin<&mut DWARF_CompilationUnit_it_variables>) -> UniquePtr<DWARF_Variable>;
        fn size(self: &DWARF_CompilationUnit_it_variables) -> u64;
    }

    impl UniquePtr<DWARF_CompilationUnit> {}
    impl UniquePtr<DWARF_CompilationUnit_it_functions> {}
    impl UniquePtr<DWARF_CompilationUnit_it_types> {}
    impl UniquePtr<DWARF_CompilationUnit_it_variables> {}
    impl CxxVector<Range> {}
}
