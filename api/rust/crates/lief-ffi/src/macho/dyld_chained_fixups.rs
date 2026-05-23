#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/DyldChainedFixups.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_ChainedBindingInfo =
            crate::macho::chained_binding_info::ffi::MachO_ChainedBindingInfo;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_DyldChainedFixups;

        fn payload(self: &MachO_DyldChainedFixups) -> Span;
        #[Self = "MachO_DyldChainedFixups"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_DyldChainedFixups) -> u32;
        fn data_size(self: &MachO_DyldChainedFixups) -> u32;
        fn fixups_version(self: &MachO_DyldChainedFixups) -> u32;
        fn starts_offset(self: &MachO_DyldChainedFixups) -> u32;
        fn imports_offset(self: &MachO_DyldChainedFixups) -> u32;
        fn symbols_offset(self: &MachO_DyldChainedFixups) -> u32;
        fn imports_count(self: &MachO_DyldChainedFixups) -> u32;
        fn symbols_format(self: &MachO_DyldChainedFixups) -> u32;
        fn imports_format(self: &MachO_DyldChainedFixups) -> u32;
        fn bindings(
            self: &MachO_DyldChainedFixups,
        ) -> UniquePtr<MachO_DyldChainedFixups_it_bindings>;

        type MachO_DyldChainedFixups_it_bindings;

        fn next(
            self: Pin<&mut MachO_DyldChainedFixups_it_bindings>,
        ) -> UniquePtr<MachO_ChainedBindingInfo>;
        fn size(self: &MachO_DyldChainedFixups_it_bindings) -> u64;
    }

    impl UniquePtr<MachO_DyldChainedFixups> {}
    impl UniquePtr<MachO_DyldChainedFixups_it_bindings> {}
}
