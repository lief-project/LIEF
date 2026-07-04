#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/PublicSymbol.hpp");

        type PDB_PublicSymbol;

        fn name(self: &PDB_PublicSymbol) -> UniquePtr<CxxString>;
        fn demangled_name(self: &PDB_PublicSymbol) -> UniquePtr<CxxString>;
        fn section_name(self: &PDB_PublicSymbol) -> UniquePtr<CxxString>;
        fn RVA(self: &PDB_PublicSymbol) -> u32;
        fn to_string(self: &PDB_PublicSymbol) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PDB_PublicSymbol> {}
}
