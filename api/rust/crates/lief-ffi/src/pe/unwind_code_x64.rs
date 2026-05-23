#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/UnwindCodeX64.hpp");

        type PE_unwind_x64_Alloc;

        #[Self = "PE_unwind_x64_Alloc"]
        fn classof(entry: &PE_unwind_x64_Code) -> bool;
        fn size(self: &PE_unwind_x64_Alloc) -> u32;

        type PE_unwind_x64_Code;

        fn position(self: &PE_unwind_x64_Code) -> u32;
        fn opcode(self: &PE_unwind_x64_Code) -> u32;
        fn to_string(self: &PE_unwind_x64_Code) -> UniquePtr<CxxString>;

        type PE_unwind_x64_Epilog;

        #[Self = "PE_unwind_x64_Epilog"]
        fn classof(entry: &PE_unwind_x64_Code) -> bool;
        fn flags(self: &PE_unwind_x64_Epilog) -> u8;
        fn size(self: &PE_unwind_x64_Epilog) -> u32;

        type PE_unwind_x64_PushMachFrame;

        #[Self = "PE_unwind_x64_PushMachFrame"]
        fn classof(entry: &PE_unwind_x64_Code) -> bool;
        fn value(self: &PE_unwind_x64_PushMachFrame) -> u8;

        type PE_unwind_x64_PushNonVol;

        #[Self = "PE_unwind_x64_PushNonVol"]
        fn classof(entry: &PE_unwind_x64_Code) -> bool;
        fn reg(self: &PE_unwind_x64_PushNonVol) -> u32;

        type PE_unwind_x64_SaveNonVolatile;

        #[Self = "PE_unwind_x64_SaveNonVolatile"]
        fn classof(entry: &PE_unwind_x64_Code) -> bool;
        fn reg(self: &PE_unwind_x64_SaveNonVolatile) -> u32;
        fn offset(self: &PE_unwind_x64_SaveNonVolatile) -> u32;

        type PE_unwind_x64_SaveXMM128;

        #[Self = "PE_unwind_x64_SaveXMM128"]
        fn classof(entry: &PE_unwind_x64_Code) -> bool;
        fn num(self: &PE_unwind_x64_SaveXMM128) -> u8;
        fn offset(self: &PE_unwind_x64_SaveXMM128) -> u32;

        type PE_unwind_x64_SetFPReg;

        #[Self = "PE_unwind_x64_SetFPReg"]
        fn classof(entry: &PE_unwind_x64_Code) -> bool;
        fn reg(self: &PE_unwind_x64_SetFPReg) -> u32;

        type PE_unwind_x64_Spare;

        #[Self = "PE_unwind_x64_Spare"]
        fn classof(entry: &PE_unwind_x64_Code) -> bool;
    }

    impl UniquePtr<PE_unwind_x64_Code> {}
    impl UniquePtr<PE_unwind_x64_Alloc> {}
    impl UniquePtr<PE_unwind_x64_Epilog> {}
    impl UniquePtr<PE_unwind_x64_PushMachFrame> {}
    impl UniquePtr<PE_unwind_x64_PushNonVol> {}
    impl UniquePtr<PE_unwind_x64_SaveNonVolatile> {}
    impl UniquePtr<PE_unwind_x64_SaveXMM128> {}
    impl UniquePtr<PE_unwind_x64_SetFPReg> {}
    impl UniquePtr<PE_unwind_x64_Spare> {}
}
