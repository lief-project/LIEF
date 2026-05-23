#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/editor/FunctionType.hpp");

        type DWARF_editor_Type = crate::dwarf::editor::type_::ffi::DWARF_editor_Type;

        type DWARF_editor_FunctionType;

        #[Self = "DWARF_editor_FunctionType"]
        fn classof(type_: &DWARF_editor_Type) -> bool;
        fn set_return_type(self: Pin<&mut DWARF_editor_FunctionType>, ty: &DWARF_editor_Type);
        fn add_parameter(
            self: Pin<&mut DWARF_editor_FunctionType>,
            ty: &DWARF_editor_Type,
        ) -> UniquePtr<DWARF_editor_FunctionType_Parameter>;

        type DWARF_editor_FunctionType_Parameter;
    }

    impl UniquePtr<DWARF_editor_FunctionType> {}
    impl UniquePtr<DWARF_editor_FunctionType_Parameter> {}
}
