#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PDB/types/ClassLike.hpp");

        type PDB_Type = crate::pdb::type_::ffi::PDB_Type;
        type PDB_types_Attribute = crate::pdb::types::attribute::ffi::PDB_types_Attribute;
        type PDB_types_Method = crate::pdb::types::method::ffi::PDB_types_Method;

        type PDB_types_Class;

        #[Self = "PDB_types_Class"]
        fn classof(type_: &PDB_Type) -> bool;

        type PDB_types_ClassLike;

        fn unique_name(self: &PDB_types_ClassLike) -> UniquePtr<CxxString>;
        fn attributes(self: &PDB_types_ClassLike) -> UniquePtr<PDB_types_ClassLike_it_attributes>;
        fn methods(self: &PDB_types_ClassLike) -> UniquePtr<PDB_types_ClassLike_it_methods>;

        type PDB_types_ClassLike_it_attributes;

        fn next(
            self: Pin<&mut PDB_types_ClassLike_it_attributes>,
        ) -> UniquePtr<PDB_types_Attribute>;
        fn size(self: &PDB_types_ClassLike_it_attributes) -> u64;

        type PDB_types_ClassLike_it_methods;

        fn next(self: Pin<&mut PDB_types_ClassLike_it_methods>) -> UniquePtr<PDB_types_Method>;
        fn size(self: &PDB_types_ClassLike_it_methods) -> u64;

        type PDB_types_Interface;

        #[Self = "PDB_types_Interface"]
        fn classof(type_: &PDB_Type) -> bool;

        type PDB_types_Structure;

        #[Self = "PDB_types_Structure"]
        fn classof(type_: &PDB_Type) -> bool;
    }
    impl UniquePtr<PDB_types_Class> {}
    impl UniquePtr<PDB_types_ClassLike> {}
    impl UniquePtr<PDB_types_ClassLike_it_attributes> {}
    impl UniquePtr<PDB_types_ClassLike_it_methods> {}
    impl UniquePtr<PDB_types_Interface> {}
    impl UniquePtr<PDB_types_Structure> {}
}
