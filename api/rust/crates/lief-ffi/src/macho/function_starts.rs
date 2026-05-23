#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/FunctionStarts.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_FunctionStarts;

        fn content(self: &MachO_FunctionStarts) -> Span;
        #[Self = "MachO_FunctionStarts"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_FunctionStarts) -> u32;
        fn data_size(self: &MachO_FunctionStarts) -> u32;
        fn functions(self: &MachO_FunctionStarts) -> UniquePtr<CxxVector<u64>>;
        fn add_function(self: Pin<&mut MachO_FunctionStarts>, address: u64);
    }

    impl UniquePtr<MachO_FunctionStarts> {}
}
