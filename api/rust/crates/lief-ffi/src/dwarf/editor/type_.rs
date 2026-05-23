#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/editor/Type.hpp");
        include!("LIEF/rust/DWARF/editor/PointerType.hpp");

        type DWARF_editor_PointerType =
            crate::dwarf::editor::pointer_type::ffi::DWARF_editor_PointerType;

        type DWARF_editor_Type;

        fn pointer_to(self: &DWARF_editor_Type) -> UniquePtr<DWARF_editor_PointerType>;
    }

    impl UniquePtr<DWARF_editor_Type> {}
}
