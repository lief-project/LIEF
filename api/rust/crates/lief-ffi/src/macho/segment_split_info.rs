#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/SegmentSplitInfo.hpp");

        type Span = crate::utils::ffi::Span;
        type MachO_Command = crate::macho::load_command::ffi::MachO_Command;

        type MachO_SegmentSplitInfo;

        fn content(self: &MachO_SegmentSplitInfo) -> Span;
        #[Self = "MachO_SegmentSplitInfo"]
        fn classof(cmd: &MachO_Command) -> bool;
        fn data_offset(self: &MachO_SegmentSplitInfo) -> u32;
        fn data_size(self: &MachO_SegmentSplitInfo) -> u32;
    }

    impl UniquePtr<MachO_SegmentSplitInfo> {}
}
