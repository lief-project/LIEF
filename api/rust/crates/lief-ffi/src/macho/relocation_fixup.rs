#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/RelocationFixup.hpp");

        type MachO_Relocation = crate::macho::relocation::ffi::MachO_Relocation;

        type MachO_RelocationFixup;

        #[Self = "MachO_RelocationFixup"]
        fn classof(reloc: &MachO_Relocation) -> bool;
        fn target(self: &MachO_RelocationFixup) -> u64;
        fn ptr_format(self: &MachO_RelocationFixup) -> u32;
        fn offset(self: &MachO_RelocationFixup) -> u32;
        fn next(self: &MachO_RelocationFixup) -> u32;
    }
    impl UniquePtr<MachO_RelocationFixup> {}
}
