#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/CompilationUnit.hpp");

        type PDB_BuildMetadata = crate::pdb::build_metadata::ffi::PDB_BuildMetadata;
        type PDB_Function = crate::pdb::function::ffi::PDB_Function;
        type LIEF_DeclOpt = crate::debug_decl_opt::ffi::LIEF_DeclOpt;

        type PDB_CompilationUnit;

        fn module_name(self: &PDB_CompilationUnit) -> UniquePtr<CxxString>;
        fn object_filename(self: &PDB_CompilationUnit) -> UniquePtr<CxxString>;
        fn sources(self: &PDB_CompilationUnit) -> UniquePtr<PDB_CompilationUnit_it_sources>;
        fn functions(self: &PDB_CompilationUnit) -> UniquePtr<PDB_CompilationUnit_it_functions>;
        fn build_metadata(self: &PDB_CompilationUnit) -> UniquePtr<PDB_BuildMetadata>;
        fn to_string(self: &PDB_CompilationUnit) -> UniquePtr<CxxString>;
        fn to_decl(self: &PDB_CompilationUnit) -> UniquePtr<CxxString>;
        fn to_decl_with_opt(self: &PDB_CompilationUnit, opt: &LIEF_DeclOpt)
            -> UniquePtr<CxxString>;

        type PDB_CompilationUnit_it_functions;

        fn next(self: Pin<&mut PDB_CompilationUnit_it_functions>) -> UniquePtr<PDB_Function>;
        fn size(self: &PDB_CompilationUnit_it_functions) -> u64;

        type PDB_CompilationUnit_it_sources;

        fn next(self: Pin<&mut PDB_CompilationUnit_it_sources>) -> UniquePtr<CxxString>;
        fn size(self: &PDB_CompilationUnit_it_sources) -> u64;
    }

    impl UniquePtr<PDB_CompilationUnit> {}
    impl UniquePtr<PDB_CompilationUnit_it_functions> {}
    impl UniquePtr<PDB_CompilationUnit_it_sources> {}
}
