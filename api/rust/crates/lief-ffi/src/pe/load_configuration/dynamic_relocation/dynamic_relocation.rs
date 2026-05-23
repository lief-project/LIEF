#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/LoadConfiguration/DynamicRelocation/DynamicRelocation.hpp");

        type PE_DynamicFixup =
            crate::pe::load_configuration::dynamic_relocation::dynamic_fixup::ffi::PE_DynamicFixup;

        type PE_DynamicRelocation;

        fn version(self: &PE_DynamicRelocation) -> u32;
        fn symbol(self: &PE_DynamicRelocation) -> u64;
        fn fixups(self: &PE_DynamicRelocation) -> UniquePtr<PE_DynamicFixup>;
        fn to_string(self: &PE_DynamicRelocation) -> UniquePtr<CxxString>;

        type PE_DynamicRelocationV1;

        #[Self = "PE_DynamicRelocationV1"]
        fn classof(entry: &PE_DynamicRelocation) -> bool;

        type PE_DynamicRelocationV2;

        #[Self = "PE_DynamicRelocationV2"]
        fn classof(entry: &PE_DynamicRelocation) -> bool;
    }

    impl UniquePtr<PE_DynamicRelocation> {}
    impl UniquePtr<PE_DynamicRelocationV1> {}
    impl UniquePtr<PE_DynamicRelocationV2> {}
}
