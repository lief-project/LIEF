#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/editor/StructType.hpp");

        type DWARF_editor_Type = crate::dwarf::editor::type_::ffi::DWARF_editor_Type;

        type DWARF_editor_StructType;

        #[Self = "DWARF_editor_StructType"]
        fn classof(type_: &DWARF_editor_Type) -> bool;
        fn set_size(self: Pin<&mut DWARF_editor_StructType>, size: u64);
        fn add_member(
            self: Pin<&mut DWARF_editor_StructType>,
            name: &CxxString,
            ty: &DWARF_editor_Type,
        ) -> UniquePtr<DWARF_editor_StructType_Member>;
        fn add_member_with_offset(
            self: Pin<&mut DWARF_editor_StructType>,
            name: &CxxString,
            ty: &DWARF_editor_Type,
            offset: u64,
        ) -> UniquePtr<DWARF_editor_StructType_Member>;
        fn add_bitfield(
            self: Pin<&mut DWARF_editor_StructType>,
            name: &CxxString,
            ty: &DWARF_editor_Type,
            bitsize: u64,
        ) -> UniquePtr<DWARF_editor_StructType_Member>;
        fn add_bitfield_with_offset(
            self: Pin<&mut DWARF_editor_StructType>,
            name: &CxxString,
            ty: &DWARF_editor_Type,
            bitsize: u64,
            offset: u64,
        ) -> UniquePtr<DWARF_editor_StructType_Member>;

        type DWARF_editor_StructType_Member;
    }

    impl UniquePtr<DWARF_editor_StructType> {}
    impl UniquePtr<DWARF_editor_StructType_Member> {}
}
