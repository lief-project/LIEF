#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/LoadConfiguration/DynamicRelocation/DynamicFixup.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_Relocation = crate::pe::relocation::ffi::PE_Relocation;

        type PE_DynamicFixup;

        fn to_string(self: &PE_DynamicFixup) -> UniquePtr<CxxString>;

        type PE_DynamicFixupARM64Kernel;

        #[Self = "PE_DynamicFixupARM64Kernel"]
        fn classof(meta: &PE_DynamicFixup) -> bool;
        fn relocations(
            self: &PE_DynamicFixupARM64Kernel,
        ) -> UniquePtr<PE_DynamicFixupARM64Kernel_it_relocations>;

        type PE_DynamicFixupARM64Kernel_entry;

        fn to_string(self: &PE_DynamicFixupARM64Kernel_entry) -> UniquePtr<CxxString>;
        fn rva(self: &PE_DynamicFixupARM64Kernel_entry) -> u32;
        fn indirect_call(self: &PE_DynamicFixupARM64Kernel_entry) -> bool;
        fn register_index(self: &PE_DynamicFixupARM64Kernel_entry) -> u8;
        fn import_type(self: &PE_DynamicFixupARM64Kernel_entry) -> u8;
        fn iat_index(self: &PE_DynamicFixupARM64Kernel_entry) -> u16;

        type PE_DynamicFixupARM64Kernel_it_relocations;

        fn next(
            self: Pin<&mut PE_DynamicFixupARM64Kernel_it_relocations>,
        ) -> UniquePtr<PE_DynamicFixupARM64Kernel_entry>;
        fn size(self: &PE_DynamicFixupARM64Kernel_it_relocations) -> u64;

        type PE_DynamicFixupARM64X;

        #[Self = "PE_DynamicFixupARM64X"]
        fn classof(meta: &PE_DynamicFixup) -> bool;
        fn relocations(
            self: &PE_DynamicFixupARM64X,
        ) -> UniquePtr<PE_DynamicFixupARM64X_it_relocations>;

        type PE_DynamicFixupARM64X_entry;

        fn get_bytes(self: &PE_DynamicFixupARM64X_entry) -> Span;
        fn rva(self: &PE_DynamicFixupARM64X_entry) -> u32;
        fn value(self: &PE_DynamicFixupARM64X_entry) -> i64;
        fn size(self: &PE_DynamicFixupARM64X_entry) -> u32;
        fn get_type(self: &PE_DynamicFixupARM64X_entry) -> u32;
        fn to_string(self: &PE_DynamicFixupARM64X_entry) -> UniquePtr<CxxString>;

        type PE_DynamicFixupARM64X_it_relocations;

        fn next(
            self: Pin<&mut PE_DynamicFixupARM64X_it_relocations>,
        ) -> UniquePtr<PE_DynamicFixupARM64X_entry>;
        fn size(self: &PE_DynamicFixupARM64X_it_relocations) -> u64;

        type PE_DynamicFixupControlTransfer;

        #[Self = "PE_DynamicFixupControlTransfer"]
        fn classof(meta: &PE_DynamicFixup) -> bool;
        fn relocations(
            self: &PE_DynamicFixupControlTransfer,
        ) -> UniquePtr<PE_DynamicFixupControlTransfer_it_relocations>;

        type PE_DynamicFixupControlTransfer_entry;

        fn rva(self: &PE_DynamicFixupControlTransfer_entry) -> u32;
        fn is_call(self: &PE_DynamicFixupControlTransfer_entry) -> bool;
        fn iat_index(self: &PE_DynamicFixupControlTransfer_entry) -> u16;
        fn to_string(self: &PE_DynamicFixupControlTransfer_entry) -> UniquePtr<CxxString>;

        type PE_DynamicFixupControlTransfer_it_relocations;

        fn next(
            self: Pin<&mut PE_DynamicFixupControlTransfer_it_relocations>,
        ) -> UniquePtr<PE_DynamicFixupControlTransfer_entry>;
        fn size(self: &PE_DynamicFixupControlTransfer_it_relocations) -> u64;

        type PE_DynamicFixupGeneric;

        #[Self = "PE_DynamicFixupGeneric"]
        fn classof(meta: &PE_DynamicFixup) -> bool;
        fn relocations(
            self: &PE_DynamicFixupGeneric,
        ) -> UniquePtr<PE_DynamicFixupGeneric_it_relocations>;

        type PE_DynamicFixupGeneric_it_relocations;

        fn next(self: Pin<&mut PE_DynamicFixupGeneric_it_relocations>) -> UniquePtr<PE_Relocation>;
        fn size(self: &PE_DynamicFixupGeneric_it_relocations) -> u64;

        type PE_DynamicFixupUnknown;

        #[Self = "PE_DynamicFixupUnknown"]
        fn classof(meta: &PE_DynamicFixup) -> bool;
        fn payload(self: &PE_DynamicFixupUnknown) -> Span;
        type PE_FunctionOverride;

        #[Self = "PE_FunctionOverride"]
        fn classof(meta: &PE_DynamicFixup) -> bool;
        fn func_overriding_info(
            self: &PE_FunctionOverride,
        ) -> UniquePtr<PE_FunctionOverride_it_func_overriding_info>;
        fn bdd_info(self: &PE_FunctionOverride) -> UniquePtr<PE_FunctionOverride_it_bdd_info>;
        fn bdd_info_at(
            self: &PE_FunctionOverride,
            offset: u32,
        ) -> UniquePtr<PE_FunctionOverride_image_bdd_info_t>;
        fn bdd_info_for(
            self: &PE_FunctionOverride,
            info: &PE_FunctionOverrideInfo,
        ) -> UniquePtr<PE_FunctionOverride_image_bdd_info_t>;

        type PE_FunctionOverrideInfo;

        fn original_rva(self: &PE_FunctionOverrideInfo) -> u32;
        fn bdd_offset(self: &PE_FunctionOverrideInfo) -> u32;
        fn rva_size(self: &PE_FunctionOverrideInfo) -> u32;
        fn base_reloc_size(self: &PE_FunctionOverrideInfo) -> u32;
        fn functions_rva(self: &PE_FunctionOverrideInfo) -> UniquePtr<CxxVector<u32>>;
        fn relocations(
            self: &PE_FunctionOverrideInfo,
        ) -> UniquePtr<PE_FunctionOverrideInfo_it_relocations>;
        fn to_string(self: &PE_FunctionOverrideInfo) -> UniquePtr<CxxString>;

        type PE_FunctionOverrideInfo_it_relocations;

        fn next(self: Pin<&mut PE_FunctionOverrideInfo_it_relocations>)
            -> UniquePtr<PE_Relocation>;
        fn size(self: &PE_FunctionOverrideInfo_it_relocations) -> u64;

        type PE_FunctionOverride_image_bdd_dynamic_relocation_t;

        fn value(self: &PE_FunctionOverride_image_bdd_dynamic_relocation_t) -> u32;
        fn left(self: &PE_FunctionOverride_image_bdd_dynamic_relocation_t) -> u16;
        fn right(self: &PE_FunctionOverride_image_bdd_dynamic_relocation_t) -> u16;

        type PE_FunctionOverride_image_bdd_info_t;

        fn payload(self: &PE_FunctionOverride_image_bdd_info_t) -> Span;
        fn version(self: &PE_FunctionOverride_image_bdd_info_t) -> u32;
        fn original_size(self: &PE_FunctionOverride_image_bdd_info_t) -> u32;
        fn original_offset(self: &PE_FunctionOverride_image_bdd_info_t) -> u32;
        fn relocations(
            self: &PE_FunctionOverride_image_bdd_info_t,
        ) -> UniquePtr<PE_FunctionOverride_image_bdd_info_t_it_relocations>;

        type PE_FunctionOverride_image_bdd_info_t_it_relocations;

        fn next(
            self: Pin<&mut PE_FunctionOverride_image_bdd_info_t_it_relocations>,
        ) -> UniquePtr<PE_FunctionOverride_image_bdd_dynamic_relocation_t>;
        fn size(self: &PE_FunctionOverride_image_bdd_info_t_it_relocations) -> u64;

        type PE_FunctionOverride_it_bdd_info;

        fn next(
            self: Pin<&mut PE_FunctionOverride_it_bdd_info>,
        ) -> UniquePtr<PE_FunctionOverride_image_bdd_info_t>;
        fn size(self: &PE_FunctionOverride_it_bdd_info) -> u64;

        type PE_FunctionOverride_it_func_overriding_info;

        fn next(
            self: Pin<&mut PE_FunctionOverride_it_func_overriding_info>,
        ) -> UniquePtr<PE_FunctionOverrideInfo>;
        fn size(self: &PE_FunctionOverride_it_func_overriding_info) -> u64;
    }

    impl UniquePtr<PE_DynamicFixup> {}
    impl UniquePtr<PE_DynamicFixupARM64Kernel> {}
    impl UniquePtr<PE_DynamicFixupARM64Kernel_entry> {}
    impl UniquePtr<PE_DynamicFixupARM64Kernel_it_relocations> {}
    impl UniquePtr<PE_DynamicFixupARM64X> {}
    impl UniquePtr<PE_DynamicFixupARM64X_entry> {}
    impl UniquePtr<PE_DynamicFixupARM64X_it_relocations> {}
    impl UniquePtr<PE_DynamicFixupControlTransfer> {}
    impl UniquePtr<PE_DynamicFixupControlTransfer_entry> {}
    impl UniquePtr<PE_DynamicFixupControlTransfer_it_relocations> {}
    impl UniquePtr<PE_DynamicFixupGeneric> {}
    impl UniquePtr<PE_DynamicFixupGeneric_it_relocations> {}
    impl UniquePtr<PE_DynamicFixupUnknown> {}
    impl UniquePtr<PE_FunctionOverride> {}
    impl UniquePtr<PE_FunctionOverride_image_bdd_dynamic_relocation_t> {}
    impl UniquePtr<PE_FunctionOverride_image_bdd_info_t> {}
    impl UniquePtr<PE_FunctionOverride_image_bdd_info_t_it_relocations> {}
    impl UniquePtr<PE_FunctionOverrideInfo> {}
    impl UniquePtr<PE_FunctionOverrideInfo_it_relocations> {}
    impl UniquePtr<PE_FunctionOverride_it_bdd_info> {}
    impl UniquePtr<PE_FunctionOverride_it_func_overriding_info> {}
}
