#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/DyldInfo.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;
        type MachO_DyldBindingInfo = crate::macho::dyld_binding_info::ffi::MachO_DyldBindingInfo;
        type MachO_ExportInfo = crate::macho::export_info::ffi::MachO_ExportInfo;

        type MachO_DyldInfo;

        fn rebase_opcodes(self: &MachO_DyldInfo) -> Span;
        fn lazy_bind_opcodes(self: &MachO_DyldInfo) -> Span;
        fn bind_opcodes(self: &MachO_DyldInfo) -> Span;
        fn export_trie(self: &MachO_DyldInfo) -> Span;
        fn weak_bind_opcodes(self: &MachO_DyldInfo) -> Span;
        #[Self = "MachO_DyldInfo"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn bindings(self: &MachO_DyldInfo) -> UniquePtr<MachO_DyldInfo_it_bindings>;
        fn exports(self: &MachO_DyldInfo) -> UniquePtr<MachO_DyldInfo_it_exports>;

        type MachO_DyldInfo_it_bindings;

        fn next(self: Pin<&mut MachO_DyldInfo_it_bindings>) -> UniquePtr<MachO_DyldBindingInfo>;
        fn size(self: &MachO_DyldInfo_it_bindings) -> u64;

        type MachO_DyldInfo_it_exports;

        fn next(self: Pin<&mut MachO_DyldInfo_it_exports>) -> UniquePtr<MachO_ExportInfo>;
        fn size(self: &MachO_DyldInfo_it_exports) -> u64;
    }

    impl UniquePtr<MachO_DyldInfo> {}
    impl UniquePtr<MachO_DyldInfo_it_bindings> {}
    impl UniquePtr<MachO_DyldInfo_it_exports> {}
}
