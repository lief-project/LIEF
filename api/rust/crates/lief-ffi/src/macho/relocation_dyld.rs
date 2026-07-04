#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/RelocationDyld.hpp");

        type MachO_Relocation = crate::macho::relocation::ffi::MachO_Relocation;

        type MachO_RelocationDyld;

        #[Self = "MachO_RelocationDyld"]
        fn classof(reloc: &MachO_Relocation) -> bool;
    }
    impl UniquePtr<MachO_RelocationDyld> {}
}
