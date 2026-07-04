#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/RuntimeFunctionAArch64.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_ExceptionInfo = crate::pe::exception_info::ffi::PE_ExceptionInfo;

        type PE_RuntimeFunctionAArch64;

        #[Self = "PE_RuntimeFunctionAArch64"]
        fn classof(entry: &PE_ExceptionInfo) -> bool;
        fn length(self: &PE_RuntimeFunctionAArch64) -> u32;
        fn flag(self: &PE_RuntimeFunctionAArch64) -> u32;
        fn rva_end(self: &PE_RuntimeFunctionAArch64) -> u32;

        type PE_unwind_aarch64_PackedFunction;

        #[Self = "PE_unwind_aarch64_PackedFunction"]
        fn classof(entry: &PE_RuntimeFunctionAArch64) -> bool;
        fn frame_size(self: &PE_unwind_aarch64_PackedFunction) -> u8;
        fn reg_I(self: &PE_unwind_aarch64_PackedFunction) -> u8;
        fn reg_F(self: &PE_unwind_aarch64_PackedFunction) -> u8;
        fn H(self: &PE_unwind_aarch64_PackedFunction) -> u8;
        fn CR(self: &PE_unwind_aarch64_PackedFunction) -> u8;

        type PE_unwind_aarch64_UnpackedFunction;

        fn unwind_code(self: &PE_unwind_aarch64_UnpackedFunction) -> Span;
        #[Self = "PE_unwind_aarch64_UnpackedFunction"]
        fn classof(entry: &PE_RuntimeFunctionAArch64) -> bool;
        fn xdata_rva(self: &PE_unwind_aarch64_UnpackedFunction) -> u32;
        fn version(self: &PE_unwind_aarch64_UnpackedFunction) -> u32;
        fn X(self: &PE_unwind_aarch64_UnpackedFunction) -> u8;
        fn E(self: &PE_unwind_aarch64_UnpackedFunction) -> u8;
        fn epilog_count(self: &PE_unwind_aarch64_UnpackedFunction) -> u16;
        fn epilog_offset(self: &PE_unwind_aarch64_UnpackedFunction) -> u16;
        fn code_words(self: &PE_unwind_aarch64_UnpackedFunction) -> u32;
        fn exception_handler(self: &PE_unwind_aarch64_UnpackedFunction) -> u32;
        fn epilog_scopes(
            self: &PE_unwind_aarch64_UnpackedFunction,
        ) -> UniquePtr<PE_unwind_aarch64_UnpackedFunction_it_const_epilog_scopes>;

        type PE_unwind_aarch64_UnpackedFunction_epilog_scope_t;

        fn start_offset(self: &PE_unwind_aarch64_UnpackedFunction_epilog_scope_t) -> u32;
        fn reserved(self: &PE_unwind_aarch64_UnpackedFunction_epilog_scope_t) -> u8;
        fn start_index(self: &PE_unwind_aarch64_UnpackedFunction_epilog_scope_t) -> u16;

        type PE_unwind_aarch64_UnpackedFunction_it_const_epilog_scopes;

        fn next(
            self: Pin<&mut PE_unwind_aarch64_UnpackedFunction_it_const_epilog_scopes>,
        ) -> UniquePtr<PE_unwind_aarch64_UnpackedFunction_epilog_scope_t>;
        fn size(self: &PE_unwind_aarch64_UnpackedFunction_it_const_epilog_scopes) -> u64;
    }
    impl UniquePtr<PE_RuntimeFunctionAArch64> {}
    impl UniquePtr<PE_unwind_aarch64_PackedFunction> {}
    impl UniquePtr<PE_unwind_aarch64_UnpackedFunction> {}
    impl UniquePtr<PE_unwind_aarch64_UnpackedFunction_epilog_scope_t> {}
    impl UniquePtr<PE_unwind_aarch64_UnpackedFunction_it_const_epilog_scopes> {}
}
