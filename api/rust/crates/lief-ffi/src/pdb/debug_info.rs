#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/DebugInfo.hpp");

        type AbstracDebugInfo = crate::generic::debug_info::ffi::AbstracDebugInfo;
        type PDB_CompilationUnit = crate::pdb::compilation_unit::ffi::PDB_CompilationUnit;
        type PDB_PublicSymbol = crate::pdb::public_symbol::ffi::PDB_PublicSymbol;
        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_DebugInfo;

        #[Self = "PDB_DebugInfo"]
        fn from_file(file: &CxxString) -> UniquePtr<PDB_DebugInfo>;
        #[Self = "PDB_DebugInfo"]
        fn classof(reloc: &AbstracDebugInfo) -> bool;
        fn age(self: &PDB_DebugInfo) -> u32;
        fn guid(self: &PDB_DebugInfo) -> UniquePtr<CxxString>;
        fn compilation_units(self: &PDB_DebugInfo)
            -> UniquePtr<PDB_DebugInfo_it_compilation_units>;
        fn public_symbols(self: &PDB_DebugInfo) -> UniquePtr<PDB_DebugInfo_it_public_symbols>;
        fn types(self: &PDB_DebugInfo) -> UniquePtr<PDB_DebugInfo_it_types>;
        fn public_symbol_by_name(
            self: &PDB_DebugInfo,
            name: &CxxString,
        ) -> UniquePtr<PDB_PublicSymbol>;
        fn find_type(self: &PDB_DebugInfo, name: &CxxString) -> UniquePtr<PDB_Type>;
        fn to_string(self: &PDB_DebugInfo) -> UniquePtr<CxxString>;
        fn find_type_by_index(self: &PDB_DebugInfo, index: u32) -> UniquePtr<PDB_Type>;

        type PDB_DebugInfo_it_compilation_units;

        fn next(
            self: Pin<&mut PDB_DebugInfo_it_compilation_units>,
        ) -> UniquePtr<PDB_CompilationUnit>;
        fn size(self: &PDB_DebugInfo_it_compilation_units) -> u64;

        type PDB_DebugInfo_it_public_symbols;

        fn next(self: Pin<&mut PDB_DebugInfo_it_public_symbols>) -> UniquePtr<PDB_PublicSymbol>;
        fn size(self: &PDB_DebugInfo_it_public_symbols) -> u64;

        type PDB_DebugInfo_it_types;

        fn next(self: Pin<&mut PDB_DebugInfo_it_types>) -> UniquePtr<PDB_Type>;
        fn size(self: &PDB_DebugInfo_it_types) -> u64;
    }
    impl UniquePtr<PDB_DebugInfo> {}
    impl UniquePtr<PDB_DebugInfo_it_compilation_units> {}
    impl UniquePtr<PDB_DebugInfo_it_public_symbols> {}
    impl UniquePtr<PDB_DebugInfo_it_types> {}
}
