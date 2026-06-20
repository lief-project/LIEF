#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/FunctionVariantFixups.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;
        type MachO_SegmentCommand = crate::macho::segment_command::ffi::MachO_SegmentCommand;

        type MachO_FunctionVariantFixups;

        fn content(self: &MachO_FunctionVariantFixups) -> Span;
        #[Self = "MachO_FunctionVariantFixups"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_FunctionVariantFixups) -> u32;
        fn data_size(self: &MachO_FunctionVariantFixups) -> u32;
        fn fixups(
            self: &MachO_FunctionVariantFixups,
        ) -> UniquePtr<MachO_FunctionVariantFixups_it_fixups>;

        type MachO_FunctionVariantFixups_Fixup;

        fn seg_offset(self: &MachO_FunctionVariantFixups_Fixup) -> u32;
        fn seg_index(self: &MachO_FunctionVariantFixups_Fixup) -> u32;
        fn variant_index(self: &MachO_FunctionVariantFixups_Fixup) -> u32;
        fn pac_auth(self: &MachO_FunctionVariantFixups_Fixup) -> bool;
        fn pac_address(self: &MachO_FunctionVariantFixups_Fixup) -> bool;
        fn pac_key(self: &MachO_FunctionVariantFixups_Fixup) -> u8;
        fn pac_diversity(self: &MachO_FunctionVariantFixups_Fixup) -> u16;
        fn segment(self: &MachO_FunctionVariantFixups_Fixup) -> UniquePtr<MachO_SegmentCommand>;
        fn to_string(self: &MachO_FunctionVariantFixups_Fixup) -> UniquePtr<CxxString>;

        type MachO_FunctionVariantFixups_it_fixups;

        fn next(
            self: Pin<&mut MachO_FunctionVariantFixups_it_fixups>,
        ) -> UniquePtr<MachO_FunctionVariantFixups_Fixup>;
        fn size(self: &MachO_FunctionVariantFixups_it_fixups) -> u64;
    }

    impl UniquePtr<MachO_FunctionVariantFixups> {}
    impl UniquePtr<MachO_FunctionVariantFixups_Fixup> {}
    impl UniquePtr<MachO_FunctionVariantFixups_it_fixups> {}
}
