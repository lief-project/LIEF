pub struct Range {
    pub start: u64,
    pub end: u64,
}

unsafe impl cxx::ExternType for Range {
    type Id = cxx::type_id!("DWARF_editor_Function_Range");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/editor/Function.hpp");

        type DWARF_editor_Function_Range = crate::dwarf::editor::function::Range;
        type DWARF_editor_Type = crate::dwarf::editor::type_::ffi::DWARF_editor_Type;
        type DWARF_editor_Variable = crate::dwarf::editor::variable::ffi::DWARF_editor_Variable;

        type DWARF_editor_Function;

        fn set_address(self: Pin<&mut DWARF_editor_Function>, addr: u64);
        fn set_low_high(self: Pin<&mut DWARF_editor_Function>, low: u64, high: u64);
        fn set_ranges(
            self: Pin<&mut DWARF_editor_Function>,
            ranges: &CxxVector<DWARF_editor_Function_Range>,
        );
        fn set_external(self: Pin<&mut DWARF_editor_Function>);
        fn set_return_type(self: Pin<&mut DWARF_editor_Function>, ty: &DWARF_editor_Type);
        fn add_parameter(
            self: Pin<&mut DWARF_editor_Function>,
            name: &CxxString,
            ty: &DWARF_editor_Type,
        ) -> UniquePtr<DWARF_editor_Function_Parameter>;
        fn create_stack_variable(
            self: Pin<&mut DWARF_editor_Function>,
            name: &CxxString,
        ) -> UniquePtr<DWARF_editor_Variable>;
        fn add_lexical_block(
            self: Pin<&mut DWARF_editor_Function>,
            start: u64,
            end: u64,
        ) -> UniquePtr<DWARF_editor_Function_LexicalBlock>;
        fn add_label(
            self: Pin<&mut DWARF_editor_Function>,
            addr: u64,
            label: &CxxString,
        ) -> UniquePtr<DWARF_editor_Function_Label>;
        fn add_description(self: Pin<&mut DWARF_editor_Function>, desc: &CxxString);

        type DWARF_editor_Function_Label;

        type DWARF_editor_Function_LexicalBlock;

        fn add_block(
            self: Pin<&mut DWARF_editor_Function_LexicalBlock>,
            start: u64,
            end: u64,
        ) -> UniquePtr<DWARF_editor_Function_LexicalBlock>;
        fn add_block_from_range(
            self: Pin<&mut DWARF_editor_Function_LexicalBlock>,
            ranges: &CxxVector<DWARF_editor_Function_Range>,
        ) -> UniquePtr<DWARF_editor_Function_LexicalBlock>;
        fn add_name(self: Pin<&mut DWARF_editor_Function_LexicalBlock>, name: &CxxString);
        fn add_description(self: Pin<&mut DWARF_editor_Function_LexicalBlock>, name: &CxxString);

        type DWARF_editor_Function_Parameter;

        fn assign_register_by_name(
            self: Pin<&mut DWARF_editor_Function_Parameter>,
            name: &CxxString,
        );
        fn assign_register_by_id(self: Pin<&mut DWARF_editor_Function_Parameter>, id: u64);
    }

    impl UniquePtr<DWARF_editor_Function> {}
    impl UniquePtr<DWARF_editor_Function_Label> {}
    impl UniquePtr<DWARF_editor_Function_LexicalBlock> {}
    impl UniquePtr<DWARF_editor_Function_Parameter> {}
    impl CxxVector<DWARF_editor_Function_Range> {}
}
