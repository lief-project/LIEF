#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/FunctionVariantFixups.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_FunctionVariantFixups;

        fn content(self: &MachO_FunctionVariantFixups) -> Span;
        #[Self = "MachO_FunctionVariantFixups"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_FunctionVariantFixups) -> u32;
        fn data_size(self: &MachO_FunctionVariantFixups) -> u32;
    }

    impl UniquePtr<MachO_FunctionVariantFixups> {}
}
