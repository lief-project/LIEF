#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/Abstract/Binary.hpp");

        type AbstracDebugInfo = crate::generic::debug_info::ffi::AbstracDebugInfo;
        type AbstractFunction = crate::generic::function::ffi::AbstractFunction;
        type AssemblerConfig_r = crate::asm::config::AssemblerConfig_r;
        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;

        type AbstractBinary;

        fn entrypoint(self: &AbstractBinary) -> u64;
        fn imagebase(self: &AbstractBinary) -> u64;
        fn virtual_size(self: &AbstractBinary) -> u64;
        fn original_size(self: &AbstractBinary) -> u64;
        fn is_pie(self: &AbstractBinary) -> bool;
        fn has_nx(self: &AbstractBinary) -> bool;
        fn offset_to_virtual_address(
            self: &AbstractBinary,
            offset: u64,
            slide: u64,
            err: Pin<&mut u32>,
        ) -> u64;
        fn debug_info(self: &AbstractBinary) -> UniquePtr<AbstracDebugInfo>;
        fn disassemble(
            self: &AbstractBinary,
            addr: u64,
            size: u64,
        ) -> UniquePtr<AbstractBinary_it_instructions>;
        fn disassemble_function(
            self: &AbstractBinary,
            function: &CxxString,
        ) -> UniquePtr<AbstractBinary_it_instructions>;
        fn assemble(
            self: Pin<&mut AbstractBinary>,
            address: u64,
            Asm: &CxxString,
        ) -> UniquePtr<CxxVector<u8>>;
        fn assemble_with_config(
            self: Pin<&mut AbstractBinary>,
            address: u64,
            Asm: &CxxString,
            ffi_config: &AssemblerConfig_r,
        ) -> UniquePtr<CxxVector<u8>>;
        fn load_debug_info(
            self: Pin<&mut AbstractBinary>,
            file: &CxxString,
        ) -> UniquePtr<AbstracDebugInfo>;
        fn page_size(self: &AbstractBinary) -> u64;
        fn get_u8(self: &AbstractBinary, addr: u64, err: Pin<&mut u32>) -> u8;
        fn get_u16(self: &AbstractBinary, addr: u64, err: Pin<&mut u32>) -> u16;
        fn get_u32(self: &AbstractBinary, addr: u64, err: Pin<&mut u32>) -> u32;
        fn get_u64(self: &AbstractBinary, addr: u64, err: Pin<&mut u32>) -> u64;
        fn disassemble_address(
            self: &AbstractBinary,
            addr: u64,
        ) -> UniquePtr<AbstractBinary_it_instructions>;
        unsafe fn disassemble_buffer(
            self: &AbstractBinary,
            ptr: *const u8,
            size: u64,
            addr: u64,
        ) -> UniquePtr<AbstractBinary_it_instructions>;

        type AbstractBinary_it_functions;

        fn next(self: Pin<&mut AbstractBinary_it_functions>) -> UniquePtr<AbstractFunction>;
        fn size(self: &AbstractBinary_it_functions) -> u64;

        type AbstractBinary_it_instructions;

        fn next(self: Pin<&mut AbstractBinary_it_instructions>) -> UniquePtr<asm_Instruction>;
    }

    impl UniquePtr<AbstractBinary> {}
    impl UniquePtr<AbstractBinary_it_functions> {}
    impl UniquePtr<AbstractBinary_it_instructions> {}
}
