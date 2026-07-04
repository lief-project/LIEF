#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/DyldExportsTrie.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;
        type MachO_ExportInfo = crate::macho::export_info::ffi::MachO_ExportInfo;

        type MachO_DyldExportsTrie;

        fn content(self: &MachO_DyldExportsTrie) -> Span;
        #[Self = "MachO_DyldExportsTrie"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_DyldExportsTrie) -> u32;
        fn data_size(self: &MachO_DyldExportsTrie) -> u32;
        fn exports(self: &MachO_DyldExportsTrie) -> UniquePtr<MachO_DyldExportsTrie_it_exports>;

        type MachO_DyldExportsTrie_it_exports;

        fn next(self: Pin<&mut MachO_DyldExportsTrie_it_exports>) -> UniquePtr<MachO_ExportInfo>;
        fn size(self: &MachO_DyldExportsTrie_it_exports) -> u64;
    }

    impl UniquePtr<MachO_DyldExportsTrie> {}
    impl UniquePtr<MachO_DyldExportsTrie_it_exports> {}
}
