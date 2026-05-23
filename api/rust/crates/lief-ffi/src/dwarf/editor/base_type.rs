#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/editor/BaseType.hpp");

        type DWARF_editor_Type = crate::dwarf::editor::type_::ffi::DWARF_editor_Type;

        type DWARF_editor_BaseType;

        #[Self = "DWARF_editor_BaseType"]
        fn classof(type_: &DWARF_editor_Type) -> bool;
    }

    impl UniquePtr<DWARF_editor_BaseType> {}
}
