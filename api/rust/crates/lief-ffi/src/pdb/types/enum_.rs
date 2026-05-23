#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/Enum.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;

        type PDB_types_Enum;

        #[Self = "PDB_types_Enum"]
        fn classof(type_: &PDB_Type) -> bool;
        fn entries(self: &PDB_types_Enum) -> UniquePtr<PDB_types_Enum_it_entries>;
        fn underlying_type(self: &PDB_types_Enum) -> UniquePtr<PDB_Type>;
        fn find_entry(self: &PDB_types_Enum, value: i64) -> UniquePtr<PDB_types_Enum_Entry>;
        fn unique_name(self: &PDB_types_Enum) -> UniquePtr<CxxString>;

        type PDB_types_Enum_Entry;

        fn name(self: &PDB_types_Enum_Entry) -> UniquePtr<CxxString>;
        fn value(self: &PDB_types_Enum_Entry) -> i64;

        type PDB_types_Enum_it_entries;

        fn next(self: Pin<&mut PDB_types_Enum_it_entries>) -> UniquePtr<PDB_types_Enum_Entry>;
        fn size(self: &PDB_types_Enum_it_entries) -> u64;
    }
    impl UniquePtr<PDB_types_Enum> {}
    impl UniquePtr<PDB_types_Enum_Entry> {}
    impl UniquePtr<PDB_types_Enum_it_entries> {}
}
