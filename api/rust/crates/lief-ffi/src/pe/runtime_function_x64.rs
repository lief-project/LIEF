#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/RuntimeFunctionX64.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_ExceptionInfo = crate::pe::exception_info::ffi::PE_ExceptionInfo;
        type PE_unwind_x64_Code = crate::pe::unwind_code_x64::ffi::PE_unwind_x64_Code;

        type PE_RuntimeFunctionX64;

        #[Self = "PE_RuntimeFunctionX64"]
        fn classof(entry: &PE_ExceptionInfo) -> bool;
        fn rva_end(self: &PE_RuntimeFunctionX64) -> u32;
        fn unwind_rva(self: &PE_RuntimeFunctionX64) -> u32;
        fn size(self: &PE_RuntimeFunctionX64) -> u32;
        fn unwind_info(
            self: &PE_RuntimeFunctionX64,
        ) -> UniquePtr<PE_RuntimeFunctionX64_unwind_info_t>;

        type PE_RuntimeFunctionX64_unwind_info_t;

        fn raw_opcodes(self: &PE_RuntimeFunctionX64_unwind_info_t) -> Span;
        fn version(self: &PE_RuntimeFunctionX64_unwind_info_t) -> u8;
        fn flags(self: &PE_RuntimeFunctionX64_unwind_info_t) -> u8;
        fn opcodes(
            self: &PE_RuntimeFunctionX64_unwind_info_t,
        ) -> UniquePtr<PE_RuntimeFunctionX64_unwind_info_t_it_opcodes>;
        fn chained(self: &PE_RuntimeFunctionX64_unwind_info_t) -> UniquePtr<PE_RuntimeFunctionX64>;
        fn to_string(self: &PE_RuntimeFunctionX64_unwind_info_t) -> UniquePtr<CxxString>;
        fn sizeof_prologue(self: &PE_RuntimeFunctionX64_unwind_info_t) -> u8;
        fn count_opcodes(self: &PE_RuntimeFunctionX64_unwind_info_t) -> u8;
        fn frame_reg(self: &PE_RuntimeFunctionX64_unwind_info_t) -> u8;
        fn frame_reg_offset(self: &PE_RuntimeFunctionX64_unwind_info_t) -> u8;
        fn handler(self: &PE_RuntimeFunctionX64_unwind_info_t, is_set: Pin<&mut u32>) -> u32;

        type PE_RuntimeFunctionX64_unwind_info_t_it_opcodes;

        fn next(
            self: Pin<&mut PE_RuntimeFunctionX64_unwind_info_t_it_opcodes>,
        ) -> UniquePtr<PE_unwind_x64_Code>;
        fn size(self: &PE_RuntimeFunctionX64_unwind_info_t_it_opcodes) -> u64;
    }
    impl UniquePtr<PE_RuntimeFunctionX64> {}
    impl UniquePtr<PE_RuntimeFunctionX64_unwind_info_t> {}
    impl UniquePtr<PE_RuntimeFunctionX64_unwind_info_t_it_opcodes> {}
}
