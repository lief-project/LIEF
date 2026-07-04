#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/LoadConfiguration/LoadConfiguration.hpp");

        type PE_CHPEMetadata = crate::pe::load_configuration::chpe_metadata::ffi::PE_CHPEMetadata;
        type PE_CodeIntegrity = crate::pe::code_integrity::ffi::PE_CodeIntegrity;
        type PE_DynamicRelocation = crate::pe::load_configuration::dynamic_relocation::dynamic_relocation::ffi::PE_DynamicRelocation;
        type PE_EnclaveConfiguration =
            crate::pe::load_configuration::enclave_configuration::ffi::PE_EnclaveConfiguration;
        type PE_VolatileMetadata =
            crate::pe::load_configuration::volatile_metadata::ffi::PE_VolatileMetadata;

        type PE_LoadConfiguration;

        fn characteristics(self: &PE_LoadConfiguration) -> u32;
        fn size(self: &PE_LoadConfiguration) -> u32;
        fn timedatestamp(self: &PE_LoadConfiguration) -> u32;
        fn major_version(self: &PE_LoadConfiguration) -> u16;
        fn minor_version(self: &PE_LoadConfiguration) -> u16;
        fn global_flags_clear(self: &PE_LoadConfiguration) -> u32;
        fn global_flags_set(self: &PE_LoadConfiguration) -> u32;
        fn critical_section_default_timeout(self: &PE_LoadConfiguration) -> u32;
        fn decommit_free_block_threshold(self: &PE_LoadConfiguration) -> u64;
        fn decommit_total_free_threshold(self: &PE_LoadConfiguration) -> u64;
        fn lock_prefix_table(self: &PE_LoadConfiguration) -> u64;
        fn maximum_allocation_size(self: &PE_LoadConfiguration) -> u64;
        fn virtual_memory_threshold(self: &PE_LoadConfiguration) -> u64;
        fn process_affinity_mask(self: &PE_LoadConfiguration) -> u64;
        fn process_heap_flags(self: &PE_LoadConfiguration) -> u32;
        fn csd_version(self: &PE_LoadConfiguration) -> u16;
        fn reserved1(self: &PE_LoadConfiguration) -> u16;
        fn dependent_load_flags(self: &PE_LoadConfiguration) -> u16;
        fn editlist(self: &PE_LoadConfiguration) -> u64;
        fn security_cookie(self: &PE_LoadConfiguration) -> u64;
        fn se_handler_table(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn se_handler_count(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn seh_functions(self: &PE_LoadConfiguration) -> UniquePtr<CxxVector<u32>>;
        fn guard_cf_check_function_pointer(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn guard_cf_dispatch_function_pointer(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn guard_cf_function_table(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn guard_cf_function_count(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn guard_cf_functions(
            self: &PE_LoadConfiguration,
        ) -> UniquePtr<PE_LoadConfiguration_it_guard_cf_functions>;
        fn code_integrity(self: &PE_LoadConfiguration) -> UniquePtr<PE_CodeIntegrity>;
        fn guard_address_taken_iat_entry_table(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn guard_address_taken_iat_entry_count(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn guard_address_taken_iat_entries(
            self: &PE_LoadConfiguration,
        ) -> UniquePtr<PE_LoadConfiguration_it_guard_address_taken_iat_entries>;
        fn guard_long_jump_target_table(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn guard_long_jump_target_count(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn guard_long_jump_targets(
            self: &PE_LoadConfiguration,
        ) -> UniquePtr<PE_LoadConfiguration_it_guard_long_jump_targets>;
        fn dynamic_value_reloc_table(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn hybrid_metadata_pointer(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn chpe_metadata_pointer(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn chpe_metadata(self: &PE_LoadConfiguration) -> UniquePtr<PE_CHPEMetadata>;
        fn guard_rf_failure_routine(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn guard_rf_failure_routine_function_pointer(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn dynamic_relocations(
            self: &PE_LoadConfiguration,
        ) -> UniquePtr<PE_LoadConfiguration_it_dynamic_relocations>;
        fn guard_rf_verify_stackpointer_function_pointer(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn enclave_configuration_ptr(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn enclave_config(self: &PE_LoadConfiguration) -> UniquePtr<PE_EnclaveConfiguration>;
        fn volatile_metadata_pointer(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn volatile_metadata(self: &PE_LoadConfiguration) -> UniquePtr<PE_VolatileMetadata>;
        fn guard_eh_continuation_table(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn guard_eh_continuation_count(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn guard_eh_continuation_functions(
            self: &PE_LoadConfiguration,
        ) -> UniquePtr<PE_LoadConfiguration_it_guard_eh_continuation>;
        fn guard_xfg_check_function_pointer(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn guard_xfg_dispatch_function_pointer(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn guard_xfg_table_dispatch_function_pointer(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn cast_guard_os_determined_failure_mode(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u64;
        fn guard_memcpy_function_pointer(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>)
            -> u64;
        fn uma_function_pointers(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u64;
        fn guard_flags(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u32;
        fn dynamic_value_reloctable_offset(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u32;
        fn dynamic_value_reloctable_section(
            self: &PE_LoadConfiguration,
            is_set: Pin<&mut u32>,
        ) -> u16;
        fn reserved2(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u16;
        fn hotpatch_table_offset(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u32;
        fn reserved3(self: &PE_LoadConfiguration, is_set: Pin<&mut u32>) -> u32;
        fn set_characteristics(self: Pin<&mut PE_LoadConfiguration>, characteristics: u32);
        fn set_size(self: Pin<&mut PE_LoadConfiguration>, value: u32);
        fn set_major_version(self: Pin<&mut PE_LoadConfiguration>, major_version: u16);
        fn set_minor_version(self: Pin<&mut PE_LoadConfiguration>, minor_version: u16);
        fn set_timedatestamp(self: Pin<&mut PE_LoadConfiguration>, timedatestamp: u32);
        fn set_global_flags_clear(self: Pin<&mut PE_LoadConfiguration>, global_flags_clear: u32);
        fn set_global_flags_set(self: Pin<&mut PE_LoadConfiguration>, global_flags_set: u32);
        fn set_critical_section_default_timeout(self: Pin<&mut PE_LoadConfiguration>, val: u32);
        fn set_decommit_free_block_threshold(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_decommit_total_free_threshold(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_lock_prefix_table(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_maximum_allocation_size(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_virtual_memory_threshold(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_process_affinity_mask(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_process_heap_flags(self: Pin<&mut PE_LoadConfiguration>, val: u32);
        fn set_csd_version(self: Pin<&mut PE_LoadConfiguration>, val: u16);
        fn set_reserved1(self: Pin<&mut PE_LoadConfiguration>, val: u16);
        fn set_dependent_load_flags(self: Pin<&mut PE_LoadConfiguration>, val: u16);
        fn set_editlist(self: Pin<&mut PE_LoadConfiguration>, val: u32);
        fn set_security_cookie(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_se_handler_table(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_se_handler_count(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_guard_cf_check_function_pointer(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_guard_cf_dispatch_function_pointer(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_guard_cf_function_table(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_guard_cf_function_count(self: Pin<&mut PE_LoadConfiguration>, val: u64);
        fn set_guard_flags(self: Pin<&mut PE_LoadConfiguration>, flags: u32);
        fn set_guard_address_taken_iat_entry_table(
            self: Pin<&mut PE_LoadConfiguration>,
            value: u64,
        );
        fn set_guard_address_taken_iat_entry_count(
            self: Pin<&mut PE_LoadConfiguration>,
            value: u64,
        );
        fn set_guard_long_jump_target_table(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_guard_long_jump_target_count(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_dynamic_value_reloc_table(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_hybrid_metadata_pointer(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_guard_rf_failure_routine(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_guard_rf_failure_routine_function_pointer(
            self: Pin<&mut PE_LoadConfiguration>,
            value: u64,
        );
        fn set_dynamic_value_reloctable_offset(self: Pin<&mut PE_LoadConfiguration>, value: u32);
        fn set_dynamic_value_reloctable_section(self: Pin<&mut PE_LoadConfiguration>, value: u16);
        fn set_reserved2(self: Pin<&mut PE_LoadConfiguration>, value: u16);
        fn set_guard_rf_verify_stackpointer_function_pointer(
            self: Pin<&mut PE_LoadConfiguration>,
            value: u64,
        );
        fn set_hotpatch_table_offset(self: Pin<&mut PE_LoadConfiguration>, value: u32);
        fn set_reserved3(self: Pin<&mut PE_LoadConfiguration>, value: u32);
        fn set_enclave_configuration_ptr(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_volatile_metadata_pointer(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_guard_eh_continuation_table(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_guard_eh_continuation_count(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_guard_xfg_check_function_pointer(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_guard_xfg_dispatch_function_pointer(
            self: Pin<&mut PE_LoadConfiguration>,
            value: u64,
        );
        fn set_guard_xfg_table_dispatch_function_pointer(
            self: Pin<&mut PE_LoadConfiguration>,
            value: u64,
        );
        fn set_cast_guard_os_determined_failure_mode(
            self: Pin<&mut PE_LoadConfiguration>,
            value: u64,
        );
        fn set_guard_memcpy_function_pointer(self: Pin<&mut PE_LoadConfiguration>, value: u64);
        fn set_uma_function_pointers(self: Pin<&mut PE_LoadConfiguration>, value: u64);

        type PE_LoadConfiguration_guard_function_t;

        fn rva(self: &PE_LoadConfiguration_guard_function_t) -> u32;
        fn extra(self: &PE_LoadConfiguration_guard_function_t) -> u32;

        type PE_LoadConfiguration_it_dynamic_relocations;

        fn next(
            self: Pin<&mut PE_LoadConfiguration_it_dynamic_relocations>,
        ) -> UniquePtr<PE_DynamicRelocation>;
        fn size(self: &PE_LoadConfiguration_it_dynamic_relocations) -> u64;

        type PE_LoadConfiguration_it_guard_address_taken_iat_entries;

        fn next(
            self: Pin<&mut PE_LoadConfiguration_it_guard_address_taken_iat_entries>,
        ) -> UniquePtr<PE_LoadConfiguration_guard_function_t>;
        fn size(self: &PE_LoadConfiguration_it_guard_address_taken_iat_entries) -> u64;

        type PE_LoadConfiguration_it_guard_cf_functions;

        fn next(
            self: Pin<&mut PE_LoadConfiguration_it_guard_cf_functions>,
        ) -> UniquePtr<PE_LoadConfiguration_guard_function_t>;
        fn size(self: &PE_LoadConfiguration_it_guard_cf_functions) -> u64;

        type PE_LoadConfiguration_it_guard_eh_continuation;

        fn next(
            self: Pin<&mut PE_LoadConfiguration_it_guard_eh_continuation>,
        ) -> UniquePtr<PE_LoadConfiguration_guard_function_t>;
        fn size(self: &PE_LoadConfiguration_it_guard_eh_continuation) -> u64;

        type PE_LoadConfiguration_it_guard_long_jump_targets;

        fn next(
            self: Pin<&mut PE_LoadConfiguration_it_guard_long_jump_targets>,
        ) -> UniquePtr<PE_LoadConfiguration_guard_function_t>;
        fn size(self: &PE_LoadConfiguration_it_guard_long_jump_targets) -> u64;
    }

    impl UniquePtr<PE_LoadConfiguration> {}
    impl UniquePtr<PE_LoadConfiguration_guard_function_t> {}
    impl UniquePtr<PE_LoadConfiguration_it_dynamic_relocations> {}
    impl UniquePtr<PE_LoadConfiguration_it_guard_address_taken_iat_entries> {}
    impl UniquePtr<PE_LoadConfiguration_it_guard_cf_functions> {}
    impl UniquePtr<PE_LoadConfiguration_it_guard_eh_continuation> {}
    impl UniquePtr<PE_LoadConfiguration_it_guard_long_jump_targets> {}
}
