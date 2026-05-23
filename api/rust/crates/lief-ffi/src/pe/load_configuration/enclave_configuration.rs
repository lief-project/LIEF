#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/LoadConfiguration/EnclaveConfiguration.hpp");

        type Span = crate::utils::ffi::Span;
        type PE_EnclaveConfiguration;

        fn family_id(self: &PE_EnclaveConfiguration) -> Span;
        fn image_id(self: &PE_EnclaveConfiguration) -> Span;
        fn size(self: &PE_EnclaveConfiguration) -> u32;
        fn min_required_config_size(self: &PE_EnclaveConfiguration) -> u32;
        fn policy_flags(self: &PE_EnclaveConfiguration) -> u32;
        fn is_debuggable(self: &PE_EnclaveConfiguration) -> bool;
        fn import_list_rva(self: &PE_EnclaveConfiguration) -> u32;
        fn import_entry_size(self: &PE_EnclaveConfiguration) -> u32;
        fn nb_imports(self: &PE_EnclaveConfiguration) -> u32;
        fn imports(self: &PE_EnclaveConfiguration)
            -> UniquePtr<PE_EnclaveConfiguration_it_imports>;
        fn image_version(self: &PE_EnclaveConfiguration) -> u32;
        fn security_version(self: &PE_EnclaveConfiguration) -> u32;
        fn enclave_size(self: &PE_EnclaveConfiguration) -> u64;
        fn nb_threads(self: &PE_EnclaveConfiguration) -> u32;
        fn enclave_flags(self: &PE_EnclaveConfiguration) -> u32;
        fn to_string(self: &PE_EnclaveConfiguration) -> UniquePtr<CxxString>;

        type PE_EnclaveConfiguration_it_imports;

        fn next(self: Pin<&mut PE_EnclaveConfiguration_it_imports>) -> UniquePtr<PE_EnclaveImport>;
        fn size(self: &PE_EnclaveConfiguration_it_imports) -> u64;

        type PE_EnclaveImport;

        fn id(self: &PE_EnclaveImport) -> Span;
        fn family_id(self: &PE_EnclaveImport) -> Span;
        fn image_id(self: &PE_EnclaveImport) -> Span;
        fn get_type(self: &PE_EnclaveImport) -> u32;
        fn min_security_version(self: &PE_EnclaveImport) -> u32;
        fn import_name_rva(self: &PE_EnclaveImport) -> u32;
        fn import_name(self: &PE_EnclaveImport) -> UniquePtr<CxxString>;
        fn reserved(self: &PE_EnclaveImport) -> u32;
        fn to_string(self: &PE_EnclaveImport) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<PE_EnclaveConfiguration> {}
    impl UniquePtr<PE_EnclaveConfiguration_it_imports> {}
    impl UniquePtr<PE_EnclaveImport> {}
}
