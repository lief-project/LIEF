#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/FunctionVariants.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_FunctionVariants;

        fn content(self: &MachO_FunctionVariants) -> Span;
        #[Self = "MachO_FunctionVariants"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_FunctionVariants) -> u32;
        fn data_size(self: &MachO_FunctionVariants) -> u32;
        fn runtime_table(
            self: &MachO_FunctionVariants,
        ) -> UniquePtr<MachO_FunctionVariants_it_runtime_table>;

        type MachO_FunctionVariants_RuntimeTable;

        fn kind(self: &MachO_FunctionVariants_RuntimeTable) -> u32;
        fn offset(self: &MachO_FunctionVariants_RuntimeTable) -> u32;
        fn entries(
            self: &MachO_FunctionVariants_RuntimeTable,
        ) -> UniquePtr<MachO_FunctionVariants_RuntimeTable_it_entries>;
        fn to_string(self: &MachO_FunctionVariants_RuntimeTable) -> UniquePtr<CxxString>;

        type MachO_FunctionVariants_RuntimeTableEntry;

        fn flag_bit_nums(self: &MachO_FunctionVariants_RuntimeTableEntry) -> Span;
        fn another_table(self: &MachO_FunctionVariants_RuntimeTableEntry) -> bool;
        fn flags(self: &MachO_FunctionVariants_RuntimeTableEntry) -> UniquePtr<CxxVector<u32>>;
        fn to_string(self: &MachO_FunctionVariants_RuntimeTableEntry) -> UniquePtr<CxxString>;
        fn implementation(self: &MachO_FunctionVariants_RuntimeTableEntry) -> u32;

        type MachO_FunctionVariants_RuntimeTable_it_entries;

        fn next(
            self: Pin<&mut MachO_FunctionVariants_RuntimeTable_it_entries>,
        ) -> UniquePtr<MachO_FunctionVariants_RuntimeTableEntry>;
        fn size(self: &MachO_FunctionVariants_RuntimeTable_it_entries) -> u64;

        type MachO_FunctionVariants_it_runtime_table;

        fn next(
            self: Pin<&mut MachO_FunctionVariants_it_runtime_table>,
        ) -> UniquePtr<MachO_FunctionVariants_RuntimeTable>;
        fn size(self: &MachO_FunctionVariants_it_runtime_table) -> u64;
    }

    impl UniquePtr<MachO_FunctionVariants> {}
    impl UniquePtr<MachO_FunctionVariants_it_runtime_table> {}
    impl UniquePtr<MachO_FunctionVariants_RuntimeTable> {}
    impl UniquePtr<MachO_FunctionVariants_RuntimeTableEntry> {}
    impl UniquePtr<MachO_FunctionVariants_RuntimeTable_it_entries> {}
}
