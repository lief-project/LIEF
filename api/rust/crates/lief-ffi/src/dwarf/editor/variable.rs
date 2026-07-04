#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/editor/Variable.hpp");

        type DWARF_editor_Type = crate::dwarf::editor::type_::ffi::DWARF_editor_Type;

        type DWARF_editor_Variable;

        fn set_external(self: Pin<&mut DWARF_editor_Variable>);
        fn set_addr(self: Pin<&mut DWARF_editor_Variable>, addr: u64);
        fn set_stack_offset(self: Pin<&mut DWARF_editor_Variable>, addr: u64);
        fn set_type(self: Pin<&mut DWARF_editor_Variable>, ty: &DWARF_editor_Type);
        fn add_description(self: Pin<&mut DWARF_editor_Variable>, desc: &CxxString);
    }

    impl UniquePtr<DWARF_editor_Variable> {}
}
