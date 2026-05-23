#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/ClassLike.hpp");

        type DWARF_Function = crate::dwarf::function::ffi::DWARF_Function;
        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_Class;

        #[Self = "DWARF_types_Class"]
        fn classof(type_: &DWARF_Type) -> bool;

        type DWARF_types_ClassLike;

        #[Self = "DWARF_types_ClassLike"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn find_member(
            self: &DWARF_types_ClassLike,
            offset: u64,
        ) -> UniquePtr<DWARF_types_ClassLike_Member>;
        fn members(self: &DWARF_types_ClassLike) -> UniquePtr<DWARF_types_ClassLike_it_members>;
        fn functions(self: &DWARF_types_ClassLike)
            -> UniquePtr<DWARF_types_ClassLike_it_functions>;

        type DWARF_types_ClassLike_Member;

        fn name(self: &DWARF_types_ClassLike_Member) -> UniquePtr<CxxString>;
        fn bit_offset(self: &DWARF_types_ClassLike_Member, err: Pin<&mut u32>) -> u64;
        fn bit_size(self: &DWARF_types_ClassLike_Member, err: Pin<&mut u32>) -> u64;
        fn offset(self: &DWARF_types_ClassLike_Member, err: Pin<&mut u32>) -> u64;
        fn is_declaration(self: &DWARF_types_ClassLike_Member) -> bool;
        fn is_external(self: &DWARF_types_ClassLike_Member) -> bool;
        fn get_type(self: &DWARF_types_ClassLike_Member) -> UniquePtr<DWARF_Type>;

        type DWARF_types_ClassLike_it_functions;

        fn next(self: Pin<&mut DWARF_types_ClassLike_it_functions>) -> UniquePtr<DWARF_Function>;
        fn size(self: &DWARF_types_ClassLike_it_functions) -> u64;

        type DWARF_types_ClassLike_it_members;

        fn next(
            self: Pin<&mut DWARF_types_ClassLike_it_members>,
        ) -> UniquePtr<DWARF_types_ClassLike_Member>;
        fn size(self: &DWARF_types_ClassLike_it_members) -> u64;

        type DWARF_types_Packed;

        #[Self = "DWARF_types_Packed"]
        fn classof(type_: &DWARF_Type) -> bool;

        type DWARF_types_Structure;

        #[Self = "DWARF_types_Structure"]
        fn classof(type_: &DWARF_Type) -> bool;

        type DWARF_types_Union;

        #[Self = "DWARF_types_Union"]
        fn classof(type_: &DWARF_Type) -> bool;
    }
    impl UniquePtr<DWARF_types_Class> {}
    impl UniquePtr<DWARF_types_ClassLike> {}
    impl UniquePtr<DWARF_types_ClassLike_it_functions> {}
    impl UniquePtr<DWARF_types_ClassLike_it_members> {}
    impl UniquePtr<DWARF_types_ClassLike_Member> {}
    impl UniquePtr<DWARF_types_Packed> {}
    impl UniquePtr<DWARF_types_Structure> {}
    impl UniquePtr<DWARF_types_Union> {}
}
