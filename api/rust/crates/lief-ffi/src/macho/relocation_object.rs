#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/MachO/RelocationObject.hpp");

        type MachO_Relocation = crate::macho::relocation::ffi::MachO_Relocation;

        type MachO_RelocationObject;

        #[Self = "MachO_RelocationObject"]
        fn classof(reloc: &MachO_Relocation) -> bool;
        fn is_scattered(self: &MachO_RelocationObject) -> bool;
    }
    impl UniquePtr<MachO_RelocationObject> {}
}
