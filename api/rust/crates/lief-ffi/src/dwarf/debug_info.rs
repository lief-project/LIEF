#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/DebugInfo.hpp");

        type AbstracDebugInfo = crate::generic::debug_info::ffi::AbstracDebugInfo;
        type DWARF_CompilationUnit = crate::dwarf::compilation_unit::ffi::DWARF_CompilationUnit;
        type DWARF_Function = crate::dwarf::function::ffi::DWARF_Function;
        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;
        type DWARF_Variable = crate::dwarf::variable::ffi::DWARF_Variable;

        type DWARF_DebugInfo;

        #[Self = "DWARF_DebugInfo"]
        fn from_file(file: &CxxString) -> UniquePtr<DWARF_DebugInfo>;
        #[Self = "DWARF_DebugInfo"]
        fn classof(reloc: &AbstracDebugInfo) -> bool;
        fn compilation_units(
            self: &DWARF_DebugInfo,
        ) -> UniquePtr<DWARF_DebugInfo_it_compilation_units>;
        fn function_by_name(self: &DWARF_DebugInfo, name: &CxxString) -> UniquePtr<DWARF_Function>;
        fn variable_by_name(self: &DWARF_DebugInfo, name: &CxxString) -> UniquePtr<DWARF_Variable>;
        fn type_by_name(self: &DWARF_DebugInfo, name: &CxxString) -> UniquePtr<DWARF_Type>;
        fn function_by_addr(self: &DWARF_DebugInfo, addr: u64) -> UniquePtr<DWARF_Function>;
        fn variable_by_addr(self: &DWARF_DebugInfo, addr: u64) -> UniquePtr<DWARF_Variable>;

        type DWARF_DebugInfo_it_compilation_units;

        fn next(
            self: Pin<&mut DWARF_DebugInfo_it_compilation_units>,
        ) -> UniquePtr<DWARF_CompilationUnit>;
        fn size(self: &DWARF_DebugInfo_it_compilation_units) -> u64;
    }
    impl UniquePtr<DWARF_DebugInfo> {}
    impl UniquePtr<DWARF_DebugInfo_it_compilation_units> {}
}
