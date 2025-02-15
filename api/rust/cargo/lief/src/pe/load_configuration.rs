use super::chpe_metadata_arm64;
use super::chpe_metadata_x86;
use super::volatile_metadata::VolatileMetadata;
use super::dynamic_relocation::DynamicRelocation;
use super::enclave_configuration::EnclaveConfiguration;
use crate::common::{into_optional, FromFFI};
use crate::pe::code_integrity::CodeIntegrity;
use crate::{declare_iterator, to_conv_opt, to_opt};
use bitflags::bitflags;
use lief_ffi as ffi;
use std::marker::PhantomData;

/// This structure represents the load configuration data associated with the
/// `IMAGE_LOAD_CONFIG_DIRECTORY`.
///
/// This structure is frequently updated by Microsoft to add new metadata.
///
/// Reference: <https://github.com/MicrosoftDocs/sdk-api/blob/cbeab4d371e8bc7e352c4d3a4c5819caa08c6a1c/sdk-api-src/content/winnt/ns-winnt-image_load_config_directory64.md#L2>
pub struct LoadConfiguration<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfiguration>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl LoadConfiguration<'_> {
    /// Characteristics of the structure which is defined by its size
    pub fn characteristics(&self) -> u32 {
        self.ptr.characteristics()
    }

    /// Size of the current structure
    pub fn size(&self) -> u32 {
        self.ptr.size()
    }

    /// The date and time stamp value
    pub fn timedatestamp(&self) -> u32 {
        self.ptr.timedatestamp()
    }

    /// Major version
    pub fn major_version(&self) -> u16 {
        self.ptr.major_version()
    }

    /// Minor version
    pub fn minor_version(&self) -> u16 {
        self.ptr.minor_version()
    }

    /// The global flags that control system behavior. For more information, see `Gflags.exe`.
    pub fn global_flags_clear(&self) -> u32 {
        self.ptr.global_flags_clear()
    }

    /// The global flags that control system behavior. For more information, see `Gflags.exe`.
    pub fn global_flags_set(&self) -> u32 {
        self.ptr.global_flags_set()
    }

    /// The critical section default time-out value.
    pub fn critical_section_default_timeout(&self) -> u32 {
        self.ptr.critical_section_default_timeout()
    }

    /// The size of the minimum block that must be freed before it is freed (de-committed), in bytes.
    /// This value is advisory.
    pub fn decommit_free_block_threshold(&self) -> u64 {
        self.ptr.decommit_free_block_threshold()
    }

    /// The size of the minimum total memory that must be freed in the process heap before it is
    /// freed (de-committed), in bytes. This value is advisory.
    pub fn decommit_total_free_threshold(&self) -> u64 {
        self.ptr.decommit_total_free_threshold()
    }

    /// The VA of a list of addresses where the `LOCK` prefix is used. These will be replaced by
    /// `NOP` on single-processor systems. This member is available only for x86.
    pub fn lock_prefix_table(&self) -> u64 {
        self.ptr.lock_prefix_table()
    }

    /// The maximum allocation size, in bytes. This member is obsolete and is used only for
    /// debugging purposes.
    pub fn maximum_allocation_size(&self) -> u64 {
        self.ptr.maximum_allocation_size()
    }

    /// The maximum block size that can be allocated from heap segments, in bytes.
    pub fn virtual_memory_threshold(&self) -> u64 {
        self.ptr.virtual_memory_threshold()
    }

    /// The process affinity mask. For more information, see `GetProcessAffinityMask`. This member
    /// is available only for `.exe` files.
    pub fn process_affinity_mask(&self) -> u64 {
        self.ptr.process_affinity_mask()
    }

    /// The process heap flags. For more information, see `HeapCreate`.
    pub fn process_heap_flags(&self) -> u32 {
        self.ptr.process_heap_flags()
    }

    /// The service pack version.
    pub fn csd_version(&self) -> u16 {
        self.ptr.csd_version()
    }

    /// See: [`LoadConfiguration::dependent_load_flags`]
    pub fn reserved1(&self) -> u16 {
        self.ptr.reserved1()
    }

    /// Alias for [`LoadConfiguration::reserved1`].
    ///
    /// The default load flags used when the operating system resolves the
    /// statically linked imports of a module. For more information, see
    /// `LoadLibraryEx`.
    pub fn dependent_load_flags(&self) -> u16 {
        self.ptr.dependent_load_flags()
    }

    /// Reserved for use by the system.
    pub fn editlist(&self) -> u32 {
        self.ptr.editlist()
    }

    /// A pointer to a cookie that is used by Visual C++ or GS implementation.
    pub fn security_cookie(&self) -> u64 {
        self.ptr.security_cookie()
    }

    /// The VA of the sorted table of RVAs of each valid, unique handler in the image. This member
    /// is available only for x86.
    pub fn se_handler_table(&self) -> Option<u64> {
        to_opt!(&lief_ffi::PE_LoadConfiguration::se_handler_table, &self);
    }

    /// The count of unique handlers in the table. This member is available only for x86.
    pub fn se_handler_count(&self) -> Option<u64> {
        to_opt!(&lief_ffi::PE_LoadConfiguration::se_handler_count, &self);
    }

    /// Return the list of the function RVA in the SEH table (if any)
    pub fn seh_functions(&self) -> Vec<u32> {
        Vec::from(self.ptr.seh_functions().as_slice())
    }

    /// The VA where Control Flow Guard check-function pointer is stored.
    pub fn guard_cf_check_function_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_cf_check_function_pointer,
            &self
        );
    }

    /// The VA where Control Flow Guard dispatch-function pointer is stored.
    pub fn guard_cf_dispatch_function_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_cf_dispatch_function_pointer,
            &self
        );
    }

    /// The VA of the sorted table of RVAs of each Control Flow Guard function in the image.
    pub fn guard_cf_function_table(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_cf_function_table,
            &self
        );
    }

    /// The count of unique RVAs in the [`LoadConfiguration::guard_cf_function_table`] table.
    pub fn guard_cf_function_count(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_cf_function_count,
            &self
        );
    }

    /// Iterator over the Control Flow Guard functions referenced by
    /// [`LoadConfiguration::guard_cf_function_table`]
    pub fn guard_cf_functions(&self) -> GuardCFFunctions {
        GuardCFFunctions::new(self.ptr.guard_cf_functions())
    }

    /// Control Flow Guard related flags.
    pub fn guard_flags(&self) -> Option<ImageGuardFlags> {
        to_conv_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_flags,
            &self,
            |e: u32| ImageGuardFlags::from(e)
        );
    }

    /// Code integrity information.
    pub fn code_integrity(&self) -> Option<CodeIntegrity> {
        into_optional(self.ptr.code_integrity())
    }

    /// The VA where Control Flow Guard address taken IAT table is stored.
    pub fn guard_address_taken_iat_entry_table(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_address_taken_iat_entry_table,
            &self
        );
    }

    /// The count of unique RVAs in the table pointed by
    /// [`LoadConfiguration::guard_address_taken_iat_entry_table`].
    pub fn guard_address_taken_iat_entry_count(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_address_taken_iat_entry_count,
            &self
        );
    }

    /// Iterator over the functions referenced by
    /// [`LoadConfiguration::guard_address_taken_iat_entry_table`]
    pub fn guard_address_taken_iat_entries(&self) -> GuardAddressTakenIATEntries {
        GuardAddressTakenIATEntries::new(self.ptr.guard_address_taken_iat_entries())
    }

    /// The VA where Control Flow Guard long jump target table is stored.
    pub fn guard_long_jump_target_table(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_long_jump_target_table,
            &self
        );
    }

    /// The count of unique RVAs in the table pointed by
    /// [`LoadConfiguration::guard_long_jump_target_table`].
    pub fn guard_long_jump_target_count(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_long_jump_target_count,
            &self
        );
    }

    /// Iterator over the functions referenced by
    /// [`LoadConfiguration::guard_long_jump_target_table`]
    pub fn guard_long_jump_targets(&self) -> GuardLongJumpTargets {
        GuardLongJumpTargets::new(self.ptr.guard_long_jump_targets())
    }

    /// VA of pointing to a `IMAGE_DYNAMIC_RELOCATION_TABLE`
    pub fn dynamic_value_reloc_table(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::dynamic_value_reloc_table,
            &self
        );
    }

    /// Alias for [`LoadConfiguration::chpe_metadata_pointer`]
    pub fn hybrid_metadata_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::hybrid_metadata_pointer,
            &self
        );
    }

    /// VA to the extra Compiled Hybrid Portable Executable (CHPE) metadata.
    pub fn chpe_metadata_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::chpe_metadata_pointer,
            &self
        );
    }

    /// Compiled Hybrid Portable Executable (CHPE) metadata (if any)
    pub fn chpe_metadata(&self) -> Option<CHPEMetadata> {
        into_optional(self.ptr.chpe_metadata())
    }

    /// VA of the failure routine
    pub fn guard_rf_failure_routine(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_rf_failure_routine,
            &self
        );
    }

    /// VA of the failure routine `fptr`.
    pub fn guard_rf_failure_routine_function_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_rf_failure_routine_function_pointer,
            &self
        );
    }

    /// Offset of dynamic relocation table relative to the relocation table
    pub fn dynamic_value_reloctable_offset(&self) -> Option<u32> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::dynamic_value_reloctable_offset,
            &self
        );
    }

    /// The section index of the dynamic value relocation table
    pub fn dynamic_value_reloctable_section(&self) -> Option<u16> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::dynamic_value_reloctable_section,
            &self
        );
    }

    /// Return an iterator over the Dynamic relocations (DVRT)
    pub fn dynamic_relocations(&self) -> DynamicRelocations {
        DynamicRelocations::new(self.ptr.dynamic_relocations())
    }

    /// Must be zero
    pub fn reserved2(&self) -> Option<u16> {
        to_opt!(&lief_ffi::PE_LoadConfiguration::reserved2, &self);
    }

    /// VA of the Function verifying the stack pointer
    pub fn guard_rf_verify_stackpointer_function_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_rf_verify_stackpointer_function_pointer,
            &self
        );
    }

    pub fn hotpatch_table_offset(&self) -> Option<u32> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::hotpatch_table_offset,
            &self
        );
    }

    pub fn reserved3(&self) -> Option<u32> {
        to_opt!(&lief_ffi::PE_LoadConfiguration::reserved3, &self);
    }

    pub fn enclave_config(&self) -> Option<EnclaveConfiguration> {
        into_optional(self.ptr.enclave_config())
    }

    pub fn enclave_configuration_ptr(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::enclave_configuration_ptr,
            &self
        );
    }

    pub fn volatile_metadata_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::volatile_metadata_pointer,
            &self
        );
    }

    pub fn volatile_metadata(&self) -> Option<VolatileMetadata> {
        into_optional(self.ptr.volatile_metadata())
    }

    pub fn guard_eh_continuation_table(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_eh_continuation_table,
            &self
        );
    }

    pub fn guard_eh_continuation_count(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_eh_continuation_count,
            &self
        );
    }

    /// Iterator over the Guard EH continuation functions referenced by
    /// [`LoadConfiguration::guard_eh_continuation_table`]
    pub fn guard_eh_continuation_functions(&self) -> GuardEhContinuationFunctions {
        GuardEhContinuationFunctions::new(self.ptr.guard_eh_continuation_functions())
    }

    pub fn guard_xfg_check_function_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_xfg_check_function_pointer,
            &self
        );
    }

    pub fn guard_xfg_dispatch_function_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_xfg_dispatch_function_pointer,
            &self
        );
    }

    pub fn guard_xfg_table_dispatch_function_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_xfg_table_dispatch_function_pointer,
            &self
        );
    }

    pub fn cast_guard_os_determined_failure_mode(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::cast_guard_os_determined_failure_mode,
            &self
        );
    }

    pub fn guard_memcpy_function_pointer(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::PE_LoadConfiguration::guard_memcpy_function_pointer,
            &self
        );
    }
}

impl<'a> FromFFI<ffi::PE_LoadConfiguration> for LoadConfiguration<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfiguration>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for LoadConfiguration<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfiguration")
            .field("size", &self.size())
            .field("timedatestamp", &self.timedatestamp())
            .field("major_version", &self.major_version())
            .field("minor_version", &self.minor_version())
            .field("global_flags_clear", &self.global_flags_clear())
            .field("global_flags_set", &self.global_flags_set())
            .field(
                "critical_section_default_timeout",
                &self.critical_section_default_timeout(),
            )
            .field(
                "decommit_free_block_threshold",
                &self.decommit_free_block_threshold(),
            )
            .field(
                "decommit_total_free_threshold",
                &self.decommit_total_free_threshold(),
            )
            .field("lock_prefix_table", &self.lock_prefix_table())
            .field("maximum_allocation_size", &self.maximum_allocation_size())
            .field("virtual_memory_threshold", &self.virtual_memory_threshold())
            .field("process_affinity_mask", &self.process_affinity_mask())
            .field("process_heap_flags", &self.process_heap_flags())
            .field("csd_version", &self.csd_version())
            .field("reserved1", &self.reserved1())
            .field("dependent_load_flags", &self.dependent_load_flags())
            .field("editlist", &self.editlist())
            .field("security_cookie", &self.security_cookie())
            .field("se_handler_table", &self.se_handler_table())
            .field("se_handler_count", &self.se_handler_count())
            .field(
                "guard_cf_check_function_pointer",
                &self.guard_cf_check_function_pointer(),
            )
            .field(
                "guard_cf_dispatch_function_pointer",
                &self.guard_cf_dispatch_function_pointer(),
            )
            .field("guard_cf_function_table", &self.guard_cf_function_table())
            .field("guard_cf_function_count", &self.guard_cf_function_count())
            .field("guard_flags", &self.guard_flags())
            .field(
                "guard_address_taken_iat_entry_table",
                &self.guard_address_taken_iat_entry_table(),
            )
            .field(
                "guard_address_taken_iat_entry_count",
                &self.guard_address_taken_iat_entry_count(),
            )
            .field(
                "guard_long_jump_target_table",
                &self.guard_long_jump_target_table(),
            )
            .field(
                "guard_long_jump_target_count",
                &self.guard_long_jump_target_count(),
            )
            .field(
                "dynamic_value_reloc_table",
                &self.dynamic_value_reloc_table(),
            )
            .field("hybrid_metadata_pointer", &self.hybrid_metadata_pointer())
            .field("chpe_metadata_pointer", &self.chpe_metadata_pointer())
            .field("guard_rf_failure_routine", &self.guard_rf_failure_routine())
            .field(
                "guard_rf_failure_routine_function_pointer",
                &self.guard_rf_failure_routine_function_pointer(),
            )
            .field(
                "dynamic_value_reloctable_offset",
                &self.dynamic_value_reloctable_offset(),
            )
            .field(
                "dynamic_value_reloctable_section",
                &self.dynamic_value_reloctable_section(),
            )
            .field("reserved2", &self.reserved2())
            .field(
                "guard_rf_verify_stackpointer_function_pointer",
                &self.guard_rf_verify_stackpointer_function_pointer(),
            )
            .field("hotpatch_table_offset", &self.hotpatch_table_offset())
            .field("reserved3", &self.reserved3())
            .field("enclave_configuration_ptr", &self.enclave_configuration_ptr())
            .field(
                "volatile_metadata_pointer",
                &self.volatile_metadata_pointer(),
            )
            .field(
                "guard_eh_continuation_table",
                &self.guard_eh_continuation_table(),
            )
            .field(
                "guard_eh_continuation_count",
                &self.guard_eh_continuation_count(),
            )
            .field(
                "guard_xfg_check_function_pointer",
                &self.guard_xfg_check_function_pointer(),
            )
            .field(
                "guard_xfg_dispatch_function_pointer",
                &self.guard_xfg_dispatch_function_pointer(),
            )
            .field(
                "guard_xfg_table_dispatch_function_pointer",
                &self.guard_xfg_table_dispatch_function_pointer(),
            )
            .field(
                "cast_guard_os_determined_failure_mode",
                &self.cast_guard_os_determined_failure_mode(),
            )
            .field(
                "guard_memcpy_function_pointer",
                &self.guard_memcpy_function_pointer(),
            )
            .finish()
    }
}

pub struct GuardFunction<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfiguration_guard_function_t>,
    _owner: PhantomData<&'a ffi::PE_LoadConfiguration>,
}

impl<'a> FromFFI<ffi::PE_LoadConfiguration_guard_function_t> for GuardFunction<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfiguration_guard_function_t>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl GuardFunction<'_> {
    /// RVA of the function
    pub fn rva(&self) -> u32 {
        self.ptr.rva()
    }

    /// Additional information whose meaning is not officially documented
    pub fn extra(&self) -> u32 {
        self.ptr.extra()
    }
}

impl std::fmt::Debug for GuardFunction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardFunction")
            .field("rva", &self.rva())
            .field("extra", &self.extra())
            .finish()
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ImageGuardFlags: u32 {
        const NONE = 0x0;
        const CF_INSTRUMENTED = 0x100;
        const CFW_INSTRUMENTED = 0x200;
        const CF_FUNCTION_TABLE_PRESENT = 0x400;
        const SECURITY_COOKIE_UNUSED = 0x800;
        const PROTECT_DELAYLOAD_IAT = 0x1000;
        const DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x2000;
        const CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x4000;
        const CF_ENABLE_EXPORT_SUPPRESSION = 0x8000;
        const CF_LONGJUMP_TABLE_PRESENT = 0x10000;
        const RF_INSTRUMENTED = 0x20000;
        const RF_ENABLE = 0x40000;
        const RF_STRICT = 0x80000;
        const RETPOLINE_PRESENT = 0x100000;
        const EH_CONTINUATION_TABLE_PRESENT = 0x200000;
    }
}

impl From<u32> for ImageGuardFlags {
    fn from(value: u32) -> Self {
        ImageGuardFlags::from_bits_truncate(value)
    }
}
impl From<ImageGuardFlags> for u32 {
    fn from(value: ImageGuardFlags) -> Self {
        value.bits()
    }
}
impl std::fmt::Display for ImageGuardFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

#[derive(Debug)]
pub enum CHPEMetadata<'a> {
    ARM64(chpe_metadata_arm64::CHPEMetadata<'a>),
    X86(chpe_metadata_x86::CHPEMetadata<'a>),
}

impl<'a> FromFFI<ffi::PE_CHPEMetadata> for CHPEMetadata<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_CHPEMetadata>) -> Self {
        unsafe {
            let obj_ref = ffi_entry.as_ref().unwrap();
            if ffi::PE_CHPEMetadataARM64::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_CHPEMetadata>;
                    type To = cxx::UniquePtr<ffi::PE_CHPEMetadataARM64>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                CHPEMetadata::ARM64(chpe_metadata_arm64::CHPEMetadata::from_ffi(raw))
            } else if ffi::PE_CHPEMetadataX86::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_CHPEMetadata>;
                    type To = cxx::UniquePtr<ffi::PE_CHPEMetadataX86>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                CHPEMetadata::X86(chpe_metadata_x86::CHPEMetadata::from_ffi(raw))
            } else {
                panic!("unsupported architecture");
            }
        }
    }
}

/// Trait shared by all architecture-specific CHPEMetadata
pub trait AsCHPEMetadata {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::PE_CHPEMetadata;

    /// Version of the structure
    fn version(&self) -> u32 {
        self.as_generic().version()
    }
}

impl std::fmt::Display for &dyn AsCHPEMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

impl AsCHPEMetadata for CHPEMetadata<'_> {
    fn as_generic(&self) -> &ffi::PE_CHPEMetadata {
        match &self {
            CHPEMetadata::ARM64(entry) => {
                entry.as_generic()
            }

            CHPEMetadata::X86(entry) => {
                entry.as_generic()
            }
        }
    }
}

declare_iterator!(
    GuardCFFunctions,
    GuardFunction<'a>,
    ffi::PE_LoadConfiguration_guard_function_t,
    ffi::PE_LoadConfiguration,
    ffi::PE_LoadConfiguration_it_guard_cf_functions
);

declare_iterator!(
    GuardAddressTakenIATEntries,
    GuardFunction<'a>,
    ffi::PE_LoadConfiguration_guard_function_t,
    ffi::PE_LoadConfiguration,
    ffi::PE_LoadConfiguration_it_guard_address_taken_iat_entries
);

declare_iterator!(
    GuardLongJumpTargets,
    GuardFunction<'a>,
    ffi::PE_LoadConfiguration_guard_function_t,
    ffi::PE_LoadConfiguration,
    ffi::PE_LoadConfiguration_it_guard_long_jump_targets
);

declare_iterator!(
    GuardEhContinuationFunctions,
    GuardFunction<'a>,
    ffi::PE_LoadConfiguration_guard_function_t,
    ffi::PE_LoadConfiguration,
    ffi::PE_LoadConfiguration_it_guard_eh_continuation
);

declare_iterator!(
    DynamicRelocations,
    DynamicRelocation<'a>,
    ffi::PE_DynamicRelocation,
    ffi::PE_LoadConfiguration,
    ffi::PE_LoadConfiguration_it_dynamic_relocations
);
