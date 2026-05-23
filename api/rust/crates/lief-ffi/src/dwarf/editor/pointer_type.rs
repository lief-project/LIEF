#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/editor/PointerType.hpp");

        type DWARF_editor_Type = crate::dwarf::editor::type_::ffi::DWARF_editor_Type;

        type DWARF_editor_PointerType;

        #[Self = "DWARF_editor_PointerType"]
        fn classof(type_: &DWARF_editor_Type) -> bool;
        fn pointer_to(self: &DWARF_editor_PointerType) -> UniquePtr<DWARF_editor_PointerType>;
    }
    impl UniquePtr<DWARF_editor_PointerType> {}
}
