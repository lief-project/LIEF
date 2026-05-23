#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/editor/CompilationUnit.hpp");

        type DWARF_editor_ArrayType = crate::dwarf::editor::array_type::ffi::DWARF_editor_ArrayType;
        type DWARF_editor_BaseType = crate::dwarf::editor::base_type::ffi::DWARF_editor_BaseType;
        type DWARF_editor_EnumType = crate::dwarf::editor::enum_type::ffi::DWARF_editor_EnumType;
        type DWARF_editor_Function = crate::dwarf::editor::function::ffi::DWARF_editor_Function;
        type DWARF_editor_FunctionType =
            crate::dwarf::editor::function_type::ffi::DWARF_editor_FunctionType;
        type DWARF_editor_PointerType =
            crate::dwarf::editor::pointer_type::ffi::DWARF_editor_PointerType;
        type DWARF_editor_StructType =
            crate::dwarf::editor::struct_type::ffi::DWARF_editor_StructType;
        type DWARF_editor_Type = crate::dwarf::editor::type_::ffi::DWARF_editor_Type;
        type DWARF_editor_TypeDef = crate::dwarf::editor::type_def::ffi::DWARF_editor_TypeDef;
        type DWARF_editor_Variable = crate::dwarf::editor::variable::ffi::DWARF_editor_Variable;

        type DWARF_editor_CompilationUnit;

        fn set_producer(self: Pin<&mut DWARF_editor_CompilationUnit>, value: &CxxString);
        fn create_function(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            name: &CxxString,
        ) -> UniquePtr<DWARF_editor_Function>;
        fn create_variable(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            name: &CxxString,
        ) -> UniquePtr<DWARF_editor_Variable>;
        fn create_generic_type(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            name: &CxxString,
        ) -> UniquePtr<DWARF_editor_Type>;
        fn create_enum(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            name: &CxxString,
        ) -> UniquePtr<DWARF_editor_EnumType>;
        fn create_typedef(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            name: &CxxString,
            ty: &DWARF_editor_Type,
        ) -> UniquePtr<DWARF_editor_TypeDef>;
        fn create_structure(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            name: &CxxString,
            kind: u32,
        ) -> UniquePtr<DWARF_editor_StructType>;
        fn create_base_type(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            name: &CxxString,
            size: u64,
            encoding: u32,
        ) -> UniquePtr<DWARF_editor_BaseType>;
        fn create_function_type(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            name: &CxxString,
        ) -> UniquePtr<DWARF_editor_FunctionType>;
        fn create_pointer_type(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            ty: &DWARF_editor_Type,
        ) -> UniquePtr<DWARF_editor_PointerType>;
        fn create_void_type(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
        ) -> UniquePtr<DWARF_editor_Type>;
        fn create_array_type(
            self: Pin<&mut DWARF_editor_CompilationUnit>,
            name: &CxxString,
            ty: &DWARF_editor_Type,
            count: u64,
        ) -> UniquePtr<DWARF_editor_ArrayType>;
    }

    impl UniquePtr<DWARF_editor_CompilationUnit> {}
}
