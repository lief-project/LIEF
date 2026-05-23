pub mod array_type;
pub mod base_type;
pub mod compilation_unit;
pub mod enum_type;
pub mod function;
pub mod function_type;
pub mod pointer_type;
pub mod struct_type;
pub mod type_;
pub mod type_def;
pub mod variable;

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/Editor.hpp");

        type AbstractBinary = crate::generic::binary::ffi::AbstractBinary;
        type DWARF_editor_CompilationUnit =
            crate::dwarf::editor::compilation_unit::ffi::DWARF_editor_CompilationUnit;

        type DWARF_Editor;

        fn create_compilation_unit(
            self: Pin<&mut DWARF_Editor>,
        ) -> UniquePtr<DWARF_editor_CompilationUnit>;

        fn write(self: Pin<&mut DWARF_Editor>, output: &CxxString);

        #[Self = "DWARF_Editor"]
        fn from_binary(bin: Pin<&mut AbstractBinary>) -> UniquePtr<DWARF_Editor>;

        #[Self = "DWARF_Editor"]
        fn create(fmt: u32, arch: u32) -> UniquePtr<DWARF_Editor>;
    }
    impl UniquePtr<DWARF_Editor> {}
}
