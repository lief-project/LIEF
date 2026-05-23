#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/editor/EnumType.hpp");

        type DWARF_editor_Type = crate::dwarf::editor::type_::ffi::DWARF_editor_Type;

        type DWARF_editor_EnumType;

        #[Self = "DWARF_editor_EnumType"]
        fn classof(type_: &DWARF_editor_Type) -> bool;
        fn set_size(self: Pin<&mut DWARF_editor_EnumType>, size: u64);
        fn set_underlying_type(self: Pin<&mut DWARF_editor_EnumType>, ty: &DWARF_editor_Type);
        fn add_value(
            self: Pin<&mut DWARF_editor_EnumType>,
            name: &CxxString,
            value: i64,
        ) -> UniquePtr<DWARF_editor_EnumType_Value>;

        type DWARF_editor_EnumType_Value;
    }

    impl UniquePtr<DWARF_editor_EnumType> {}
    impl UniquePtr<DWARF_editor_EnumType_Value> {}
}
