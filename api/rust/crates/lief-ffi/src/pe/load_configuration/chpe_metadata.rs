#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/LoadConfiguration/CHPEMetadata.hpp");

        type PE_CHPEMetadata;

        fn version(self: &PE_CHPEMetadata) -> u32;
        fn to_string(self: &PE_CHPEMetadata) -> UniquePtr<CxxString>;

        type PE_CHPEMetadataARM64;

        #[Self = "PE_CHPEMetadataARM64"]
        fn classof(meta: &PE_CHPEMetadata) -> bool;
        fn code_map(self: &PE_CHPEMetadataARM64) -> u32;
        fn code_map_count(self: &PE_CHPEMetadataARM64) -> u32;
        fn code_ranges_to_entrypoints(self: &PE_CHPEMetadataARM64) -> u32;
        fn redirection_metadata(self: &PE_CHPEMetadataARM64) -> u32;
        fn os_arm64x_dispatch_call_no_redirect(self: &PE_CHPEMetadataARM64) -> u32;
        fn os_arm64x_dispatch_ret(self: &PE_CHPEMetadataARM64) -> u32;
        fn os_arm64x_dispatch_call(self: &PE_CHPEMetadataARM64) -> u32;
        fn os_arm64x_dispatch_icall(self: &PE_CHPEMetadataARM64) -> u32;
        fn os_arm64x_dispatch_icall_cfg(self: &PE_CHPEMetadataARM64) -> u32;
        fn alternate_entry_point(self: &PE_CHPEMetadataARM64) -> u32;
        fn auxiliary_iat(self: &PE_CHPEMetadataARM64) -> u32;
        fn code_ranges_to_entry_points_count(self: &PE_CHPEMetadataARM64) -> u32;
        fn redirection_metadata_count(self: &PE_CHPEMetadataARM64) -> u32;
        fn get_x64_information_function_pointer(self: &PE_CHPEMetadataARM64) -> u32;
        fn set_x64_information_function_pointer(self: &PE_CHPEMetadataARM64) -> u32;
        fn extra_rfe_table(self: &PE_CHPEMetadataARM64) -> u32;
        fn extra_rfe_table_size(self: &PE_CHPEMetadataARM64) -> u32;
        fn os_arm64x_dispatch_fptr(self: &PE_CHPEMetadataARM64) -> u32;
        fn auxiliary_iat_copy(self: &PE_CHPEMetadataARM64) -> u32;
        fn auxiliary_delay_import(self: &PE_CHPEMetadataARM64) -> u32;
        fn auxiliary_delay_import_copy(self: &PE_CHPEMetadataARM64) -> u32;
        fn bitfield_info(self: &PE_CHPEMetadataARM64) -> u32;
        fn code_ranges(
            self: &PE_CHPEMetadataARM64,
        ) -> UniquePtr<PE_CHPEMetadataARM64_it_const_range_entries>;
        fn redirections(
            self: &PE_CHPEMetadataARM64,
        ) -> UniquePtr<PE_CHPEMetadataARM64_it_const_redirection_entries>;
        fn code_range_entry_point(
            self: &PE_CHPEMetadataARM64,
        ) -> UniquePtr<PE_CHPEMetadataARM64_it_const_code_range_entry_point>;

        type PE_CHPEMetadataARM64_code_range_entry_point_t;

        fn start_rva(self: &PE_CHPEMetadataARM64_code_range_entry_point_t) -> u32;
        fn entrypoint(self: &PE_CHPEMetadataARM64_code_range_entry_point_t) -> u32;
        fn end_rva(self: &PE_CHPEMetadataARM64_code_range_entry_point_t) -> u32;

        type PE_CHPEMetadataARM64_it_const_code_range_entry_point;

        fn next(
            self: Pin<&mut PE_CHPEMetadataARM64_it_const_code_range_entry_point>,
        ) -> UniquePtr<PE_CHPEMetadataARM64_code_range_entry_point_t>;
        fn size(self: &PE_CHPEMetadataARM64_it_const_code_range_entry_point) -> u64;

        type PE_CHPEMetadataARM64_it_const_range_entries;

        fn next(
            self: Pin<&mut PE_CHPEMetadataARM64_it_const_range_entries>,
        ) -> UniquePtr<PE_CHPEMetadataARM64_range_entry_t>;
        fn size(self: &PE_CHPEMetadataARM64_it_const_range_entries) -> u64;

        type PE_CHPEMetadataARM64_it_const_redirection_entries;

        fn next(
            self: Pin<&mut PE_CHPEMetadataARM64_it_const_redirection_entries>,
        ) -> UniquePtr<PE_CHPEMetadataARM64_redirection_entry_t>;
        fn size(self: &PE_CHPEMetadataARM64_it_const_redirection_entries) -> u64;

        type PE_CHPEMetadataARM64_redirection_entry_t;

        fn src(self: &PE_CHPEMetadataARM64_redirection_entry_t) -> u32;
        fn dst(self: &PE_CHPEMetadataARM64_redirection_entry_t) -> u32;

        type PE_CHPEMetadataARM64_range_entry_t;

        fn length(self: &PE_CHPEMetadataARM64_range_entry_t) -> u32;
        fn start(self: &PE_CHPEMetadataARM64_range_entry_t) -> u32;
        fn get_type(self: &PE_CHPEMetadataARM64_range_entry_t) -> u32;
        fn end(self: &PE_CHPEMetadataARM64_range_entry_t) -> u32;
        fn start_offset(self: &PE_CHPEMetadataARM64_range_entry_t) -> u32;

        type PE_CHPEMetadataX86;

        #[Self = "PE_CHPEMetadataX86"]
        fn classof(meta: &PE_CHPEMetadata) -> bool;
        fn chpe_code_address_range_offset(self: &PE_CHPEMetadataX86) -> u32;
        fn chpe_code_address_range_count(self: &PE_CHPEMetadataX86) -> u32;
        fn wowa64_exception_handler_function_pointer(self: &PE_CHPEMetadataX86) -> u32;
        fn wowa64_dispatch_call_function_pointer(self: &PE_CHPEMetadataX86) -> u32;
        fn wowa64_dispatch_indirect_call_function_pointer(self: &PE_CHPEMetadataX86) -> u32;
        fn wowa64_dispatch_indirect_call_cfg_function_pointer(self: &PE_CHPEMetadataX86) -> u32;
        fn wowa64_dispatch_ret_function_pointer(self: &PE_CHPEMetadataX86) -> u32;
        fn wowa64_dispatch_ret_leaf_function_pointer(self: &PE_CHPEMetadataX86) -> u32;
        fn wowa64_dispatch_jump_function_pointer(self: &PE_CHPEMetadataX86) -> u32;
        fn compiler_iat_pointer(self: &PE_CHPEMetadataX86, is_set: Pin<&mut u32>) -> u32;
        fn wowa64_rdtsc_function_pointer(self: &PE_CHPEMetadataX86, is_set: Pin<&mut u32>) -> u32;
    }

    impl UniquePtr<PE_CHPEMetadata> {}
    impl UniquePtr<PE_CHPEMetadataARM64> {}
    impl UniquePtr<PE_CHPEMetadataARM64_code_range_entry_point_t> {}
    impl UniquePtr<PE_CHPEMetadataARM64_it_const_code_range_entry_point> {}
    impl UniquePtr<PE_CHPEMetadataARM64_it_const_range_entries> {}
    impl UniquePtr<PE_CHPEMetadataARM64_it_const_redirection_entries> {}
    impl UniquePtr<PE_CHPEMetadataARM64_range_entry_t> {}
    impl UniquePtr<PE_CHPEMetadataARM64_redirection_entry_t> {}
    impl UniquePtr<PE_CHPEMetadataX86> {}
}
