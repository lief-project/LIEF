#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/DataInCode.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;
        type MachO_DataCodeEntry = crate::macho::data_code_entry::ffi::MachO_DataCodeEntry;

        type MachO_DataInCode;

        fn content(self: &MachO_DataInCode) -> Span;
        #[Self = "MachO_DataInCode"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_DataInCode) -> u32;
        fn data_size(self: &MachO_DataInCode) -> u32;
        fn entries(self: &MachO_DataInCode) -> UniquePtr<MachO_DataInCode_it_entries>;

        type MachO_DataInCode_it_entries;

        fn next(self: Pin<&mut MachO_DataInCode_it_entries>) -> UniquePtr<MachO_DataCodeEntry>;
        fn size(self: &MachO_DataInCode_it_entries) -> u64;
    }

    impl UniquePtr<MachO_DataInCode> {}
    impl UniquePtr<MachO_DataInCode_it_entries> {}
}
