#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/Variable.hpp");

        type DWARF_Location = crate::dwarf::location::ffi::DWARF_Location;
        type DWARF_Scope = crate::dwarf::scope::ffi::DWARF_Scope;
        type DWARF_it_locations = crate::dwarf::location::ffi::DWARF_it_locations;
        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;
        type DebugLocation = crate::debug_location::ffi::DebugLocation;
        type LIEF_DeclOpt = crate::debug_decl_opt::ffi::LIEF_DeclOpt;

        type DWARF_Variable;

        fn name(self: &DWARF_Variable) -> UniquePtr<CxxString>;
        fn linkage_name(self: &DWARF_Variable) -> UniquePtr<CxxString>;
        fn address(self: &DWARF_Variable, err: Pin<&mut u32>) -> i64;
        fn size(self: &DWARF_Variable, err: Pin<&mut u32>) -> u64;
        fn debug_location(self: &DWARF_Variable) -> UniquePtr<DebugLocation>;
        fn is_constexpr(self: &DWARF_Variable) -> bool;
        fn is_stack_based(self: &DWARF_Variable) -> bool;
        fn location(self: &DWARF_Variable) -> UniquePtr<DWARF_Location>;
        fn location_at(self: &DWARF_Variable, pc: u64) -> UniquePtr<DWARF_Location>;
        fn locations(self: &DWARF_Variable) -> UniquePtr<DWARF_it_locations>;
        fn get_type(self: &DWARF_Variable) -> UniquePtr<DWARF_Type>;
        fn scope(self: &DWARF_Variable) -> UniquePtr<DWARF_Scope>;
        fn description(self: &DWARF_Variable) -> UniquePtr<CxxString>;
        fn to_decl(self: &DWARF_Variable) -> UniquePtr<CxxString>;
        fn to_decl_with_opt(self: &DWARF_Variable, opt: &LIEF_DeclOpt) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<DWARF_Variable> {}
}
