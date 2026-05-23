#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/Function.hpp");

        type DebugLocation = crate::debug_location::ffi::DebugLocation;

        type PDB_Function;

        fn name(self: &PDB_Function) -> UniquePtr<CxxString>;
        fn RVA(self: &PDB_Function) -> u32;
        fn code_size(self: &PDB_Function) -> u32;
        fn section_name(self: &PDB_Function) -> UniquePtr<CxxString>;
        fn debug_location(self: &PDB_Function) -> UniquePtr<DebugLocation>;
        fn to_string(self: &PDB_Function) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PDB_Function> {}
}
