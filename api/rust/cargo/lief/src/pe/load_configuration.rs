use std::marker::PhantomData;
use crate::common::FromFFI;
use crate::pe::code_integrity::CodeIntegrity;
use lief_ffi as ffi;

#[derive(Debug)]
pub enum LoadConfiguration<'a> {
    Base(Base<'a>),
    V0(LoadConfigV0<'a>),
    V1(LoadConfigV1<'a>),
    V2(LoadConfigV2<'a>),
    V3(LoadConfigV3<'a>),
    V4(LoadConfigV4<'a>),
    V5(LoadConfigV5<'a>),
    V6(LoadConfigV6<'a>),
    V7(LoadConfigV7<'a>),
    V8(LoadConfigV8<'a>),
    V9(LoadConfigV9<'a>),
    V10(LoadConfigV10<'a>),
    V11(LoadConfigV11<'a>),
}


impl<'a> FromFFI<ffi::PE_LoadConfiguration> for LoadConfiguration<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_LoadConfiguration>) -> Self {
        unsafe {
            let config_ref = ffi_entry.as_ref().unwrap();

            if ffi::PE_LoadConfigurationV0::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV0>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V0(LoadConfigV0::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV1::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV1>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V1(LoadConfigV1::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV2::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV2>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V2(LoadConfigV2::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV3::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV3>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V3(LoadConfigV3::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV4::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV4>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V4(LoadConfigV4::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV5::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV5>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V5(LoadConfigV5::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV6::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV6>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V6(LoadConfigV6::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV7::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV7>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V7(LoadConfigV7::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV8::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV8>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V8(LoadConfigV8::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV9::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV9>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V9(LoadConfigV9::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV10::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV10>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V10(LoadConfigV10::from_ffi(raw))
            } else if ffi::PE_LoadConfigurationV11::classof(config_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_LoadConfiguration>;
                    type To = cxx::UniquePtr<ffi::PE_LoadConfigurationV11>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                LoadConfiguration::V11(LoadConfigV11::from_ffi(raw))
            } else {
                LoadConfiguration::Base(Base::from_ffi(ffi_entry))
            }
        }
    }
}

pub struct Base<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfiguration>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for Base<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsBase;
        f.write_str(format!("{base:?}").as_str())
    }
}

impl std::fmt::Debug for &dyn AsBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Base")
            .field("characteristics", &self.characteristics())
            .field("timedatestamp", &self.timedatestamp())
            .field("major_version", &self.major_version())
            .field("minor_version", &self.minor_version())
            .field("global_flags_clear", &self.global_flags_clear())
            .field("global_flags_set", &self.global_flags_set())
            .field("critical_section_default_timeout", &self.critical_section_default_timeout())
            .field("decommit_free_block_threshold", &self.decommit_free_block_threshold())
            .field("decommit_total_free_threshold", &self.decommit_total_free_threshold())
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
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_LoadConfiguration> for Base<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfiguration>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsBase {
    #[doc(hidden)]
    fn as_base(&self) -> &ffi::PE_LoadConfiguration;

    fn characteristics(&self) -> u32 {
        self.as_base().characteristics()
    }

    fn size(&self) -> u32 {
        self.as_base().size()
    }

    fn timedatestamp(&self) -> u32 {
        self.as_base().timedatestamp()
    }

    fn major_version(&self) -> u32 {
        self.as_base().major_version()
    }

    fn minor_version(&self) -> u32 {
        self.as_base().minor_version()
    }

    fn global_flags_clear(&self) -> u32 {
        self.as_base().global_flags_clear()
    }

    fn global_flags_set(&self) -> u32 {
        self.as_base().global_flags_set()
    }

    fn critical_section_default_timeout(&self) -> u32 {
        self.as_base().critical_section_default_timeout()
    }

    fn decommit_free_block_threshold(&self) -> u64 {
        self.as_base().decommit_free_block_threshold()
    }

    fn decommit_total_free_threshold(&self) -> u64 {
        self.as_base().decommit_total_free_threshold()
    }

    fn lock_prefix_table(&self) -> u64 {
        self.as_base().lock_prefix_table()
    }

    fn maximum_allocation_size(&self) -> u64 {
        self.as_base().maximum_allocation_size()
    }

    fn virtual_memory_threshold(&self) -> u64 {
        self.as_base().virtual_memory_threshold()
    }

    fn process_affinity_mask(&self) -> u64 {
        self.as_base().process_affinity_mask()
    }

    fn process_heap_flags(&self) -> u32 {
        self.as_base().process_heap_flags()
    }

    fn csd_version(&self) -> u16 {
        self.as_base().csd_version()
    }

    fn reserved1(&self) -> u16 {
        self.as_base().reserved1()
    }

    fn dependent_load_flags(&self) -> u16 {
        self.as_base().dependent_load_flags()
    }

    fn editlist(&self) -> u32 {
        self.as_base().editlist()
    }

    fn security_cookie(&self) -> u32 {
        self.as_base().security_cookie()
    }
}

impl AsBase for Base<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV0<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV0>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for LoadConfigV0<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV0;
        f.write_str(format!("{base:?}").as_str())
    }
}

impl std::fmt::Debug for &dyn AsLoadConfigV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV0")
            .field("se_handler_table", &self.se_handler_table())
            .field("se_handler_count", &self.se_handler_count())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_LoadConfigurationV0> for LoadConfigV0<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV0>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsLoadConfigV0 {
    #[doc(hidden)]
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0;

    fn se_handler_table(&self) -> u64 {
        self.as_v0().se_handler_table()
    }

    fn se_handler_count(&self) -> u64 {
        self.as_v0().se_handler_count()
    }
}

impl AsBase for LoadConfigV0<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV0<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV1<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV1>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl<'a> FromFFI<ffi::PE_LoadConfigurationV1> for LoadConfigV1<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV1>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for LoadConfigV1<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV1;
        f.write_str(format!("{base:?}").as_str())
    }
}

impl std::fmt::Debug for &dyn AsLoadConfigV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV1")
            .field("guard_cf_check_function_pointer", &self.guard_cf_check_function_pointer())
            .field("guard_cf_dispatch_function_pointer", &self.guard_cf_dispatch_function_pointer())
            .field("guard_cf_function_table", &self.guard_cf_function_table())
            .field("guard_cf_function_count", &self.guard_cf_function_count())
            .field("guard_flags", &self.guard_flags())
            .finish()
    }
}

pub trait AsLoadConfigV1 {
    #[doc(hidden)]
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1;

    fn guard_cf_check_function_pointer(&self) -> u64 {
        self.as_v1().guard_cf_check_function_pointer()
    }

    fn guard_cf_dispatch_function_pointer(&self) -> u64 {
        self.as_v1().guard_cf_dispatch_function_pointer()
    }

    fn guard_cf_function_table(&self) -> u64 {
        self.as_v1().guard_cf_function_table()
    }

    fn guard_cf_function_count(&self) -> u64 {
        self.as_v1().guard_cf_function_count()
    }

    fn guard_flags(&self) -> u32 {
        self.as_v1().guard_flags()
    }
}

impl AsBase for LoadConfigV1<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV1<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV1<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV2<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV2>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}


impl std::fmt::Debug for LoadConfigV2<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV2;
        f.write_str(format!("{base:?}").as_str())
    }
}

impl std::fmt::Debug for &dyn AsLoadConfigV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV2")
            .field("code_integrity", &self.code_integrity())
            .finish()
    }
}


impl<'a> FromFFI<ffi::PE_LoadConfigurationV2> for LoadConfigV2<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV2>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}


pub trait AsLoadConfigV2 {
    #[doc(hidden)]
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2;

    fn code_integrity(&self) -> CodeIntegrity {
        CodeIntegrity::from_ffi(self.as_v2().code_integrity())
    }
}

impl AsBase for LoadConfigV2<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV2<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV2<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV2<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV3<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV3>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for LoadConfigV3<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV3;
        f.write_str(format!("{base:?}").as_str())
    }
}


impl std::fmt::Debug for &dyn AsLoadConfigV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV3")
            .field("guard_address_taken_iat_entry_table", &self.guard_address_taken_iat_entry_table())
            .field("guard_address_taken_iat_entry_count", &self.guard_address_taken_iat_entry_count())
            .field("guard_long_jump_target_table", &self.guard_long_jump_target_table())
            .field("guard_long_jump_target_count", &self.guard_long_jump_target_count())
            .finish()
    }
}


impl<'a> FromFFI<ffi::PE_LoadConfigurationV3> for LoadConfigV3<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV3>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}


pub trait AsLoadConfigV3 {
    #[doc(hidden)]
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3;

    fn guard_address_taken_iat_entry_table(&self) -> u64 {
        self.as_v3().guard_address_taken_iat_entry_table()
    }

    fn guard_address_taken_iat_entry_count(&self) -> u64 {
        self.as_v3().guard_address_taken_iat_entry_count()
    }

    fn guard_long_jump_target_table(&self) -> u64 {
        self.as_v3().guard_long_jump_target_table()
    }

    fn guard_long_jump_target_count(&self) -> u64 {
        self.as_v3().guard_long_jump_target_count()
    }
}

impl AsBase for LoadConfigV3<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV3<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV3<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV3<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV3 for LoadConfigV3<'_> {
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV4<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV4>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for LoadConfigV4<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV4;
        f.write_str(format!("{base:?}").as_str())
    }
}


impl std::fmt::Debug for &dyn AsLoadConfigV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV4")
            .field("dynamic_value_reloc_table", &self.dynamic_value_reloc_table())
            .field("hybrid_metadata_pointer", &self.hybrid_metadata_pointer())
            .finish()
    }
}


impl<'a> FromFFI<ffi::PE_LoadConfigurationV4> for LoadConfigV4<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV4>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsLoadConfigV4 {
    #[doc(hidden)]
    fn as_v4(&self) -> &ffi::PE_LoadConfigurationV4;

    fn dynamic_value_reloc_table(&self) -> u64 {
        self.as_v4().dynamic_value_reloc_table()
    }

    fn hybrid_metadata_pointer(&self) -> u64 {
        self.as_v4().hybrid_metadata_pointer()
    }
}

impl AsBase for LoadConfigV4<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV4<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV4<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV4<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV3 for LoadConfigV4<'_> {
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV4 for LoadConfigV4<'_> {
    fn as_v4(&self) -> &ffi::PE_LoadConfigurationV4 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV5<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV5>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for LoadConfigV5<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV5;
        f.write_str(format!("{base:?}").as_str())
    }
}


impl std::fmt::Debug for &dyn AsLoadConfigV5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV5")
            .field("guard_rf_failure_routine", &self.guard_rf_failure_routine())
            .field("guard_rf_failure_routine_function_pointer", &self.guard_rf_failure_routine_function_pointer())
            .field("dynamic_value_reloctable_offset", &self.dynamic_value_reloctable_offset())
            .field("dynamic_value_reloctable_section", &self.dynamic_value_reloctable_section())
            .field("reserved2", &self.reserved2())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_LoadConfigurationV5> for LoadConfigV5<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV5>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsLoadConfigV5 {
    #[doc(hidden)]
    fn as_v5(&self) -> &ffi::PE_LoadConfigurationV5;

    fn guard_rf_failure_routine(&self) -> u64 {
        self.as_v5().guard_rf_failure_routine()
    }

    fn guard_rf_failure_routine_function_pointer(&self) -> u64 {
        self.as_v5().guard_rf_failure_routine_function_pointer()
    }

    fn dynamic_value_reloctable_offset(&self) -> u32 {
        self.as_v5().dynamic_value_reloctable_offset()
    }

    fn dynamic_value_reloctable_section(&self) -> u16 {
        self.as_v5().dynamic_value_reloctable_section()
    }

    fn reserved2(&self) -> u16 {
        self.as_v5().reserved2()
    }
}

impl AsBase for LoadConfigV5<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV5<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV5<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV5<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV3 for LoadConfigV5<'_> {
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV4 for LoadConfigV5<'_> {
    fn as_v4(&self) -> &ffi::PE_LoadConfigurationV4 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV5 for LoadConfigV5<'_> {
    fn as_v5(&self) -> &ffi::PE_LoadConfigurationV5 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV6<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV6>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for LoadConfigV6<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV6;
        f.write_str(format!("{base:?}").as_str())
    }
}


impl std::fmt::Debug for &dyn AsLoadConfigV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV6")
            .field("guard_rf_verify_stackpointer_function_pointer", &self.guard_rf_verify_stackpointer_function_pointer())
            .field("hotpatch_table_offset", &self.hotpatch_table_offset())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_LoadConfigurationV6> for LoadConfigV6<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV6>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsLoadConfigV6 {
    #[doc(hidden)]
    fn as_v6(&self) -> &ffi::PE_LoadConfigurationV6;

    fn guard_rf_verify_stackpointer_function_pointer(&self) -> u64 {
        self.as_v6().guard_rf_verify_stackpointer_function_pointer()
    }

    fn hotpatch_table_offset(&self) -> u32 {
        self.as_v6().hotpatch_table_offset()
    }
}

impl AsBase for LoadConfigV6<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV6<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV6<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV6<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV3 for LoadConfigV6<'_> {
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3 {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV4 for LoadConfigV6<'_> {
    fn as_v4(&self) -> &ffi::PE_LoadConfigurationV4 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV5 for LoadConfigV6<'_> {
    fn as_v5(&self) -> &ffi::PE_LoadConfigurationV5 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV6 for LoadConfigV6<'_> {
    fn as_v6(&self) -> &ffi::PE_LoadConfigurationV6 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV7<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV7>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}


impl std::fmt::Debug for LoadConfigV7<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV7;
        f.write_str(format!("{base:?}").as_str())
    }
}


impl std::fmt::Debug for &dyn AsLoadConfigV7 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV7")
            .field("reserved3", &self.reserved3())
            .field("addressof_unicode_string", &self.addressof_unicode_string())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_LoadConfigurationV7> for LoadConfigV7<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV7>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsLoadConfigV7 {
    #[doc(hidden)]
    fn as_v7(&self) -> &ffi::PE_LoadConfigurationV7;

    fn reserved3(&self) -> u32 {
        self.as_v7().reserved3()
    }

    fn addressof_unicode_string(&self) -> u64 {
        self.as_v7().addressof_unicode_string()
    }
}

impl AsBase for LoadConfigV7<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV7<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV7<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV7<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV3 for LoadConfigV7<'_> {
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV4 for LoadConfigV7<'_> {
    fn as_v4(&self) -> &ffi::PE_LoadConfigurationV4 {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV5 for LoadConfigV7<'_> {
    fn as_v5(&self) -> &ffi::PE_LoadConfigurationV5 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV6 for LoadConfigV7<'_> {
    fn as_v6(&self) -> &ffi::PE_LoadConfigurationV6 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV7 for LoadConfigV7<'_> {
    fn as_v7(&self) -> &ffi::PE_LoadConfigurationV7 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV8<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV8>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}


impl std::fmt::Debug for LoadConfigV8<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV8;
        f.write_str(format!("{base:?}").as_str())
    }
}


impl std::fmt::Debug for &dyn AsLoadConfigV8 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV8")
            .field("volatile_metadata_pointer", &self.volatile_metadata_pointer())
            .finish()
    }
}


impl<'a> FromFFI<ffi::PE_LoadConfigurationV8> for LoadConfigV8<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV8>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsLoadConfigV8 {
    #[doc(hidden)]
    fn as_v8(&self) -> &ffi::PE_LoadConfigurationV8;

    fn volatile_metadata_pointer(&self) -> u64 {
        self.as_v8().volatile_metadata_pointer()
    }
}

impl AsBase for LoadConfigV8<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV8<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV8<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV8<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV3 for LoadConfigV8<'_> {
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV4 for LoadConfigV8<'_> {
    fn as_v4(&self) -> &ffi::PE_LoadConfigurationV4 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV5 for LoadConfigV8<'_> {
    fn as_v5(&self) -> &ffi::PE_LoadConfigurationV5 {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV6 for LoadConfigV8<'_> {
    fn as_v6(&self) -> &ffi::PE_LoadConfigurationV6 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV7 for LoadConfigV8<'_> {
    fn as_v7(&self) -> &ffi::PE_LoadConfigurationV7 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV8 for LoadConfigV8<'_> {
    fn as_v8(&self) -> &ffi::PE_LoadConfigurationV8 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV9<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV9>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for LoadConfigV9<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV9;
        f.write_str(format!("{base:?}").as_str())
    }
}


impl std::fmt::Debug for &dyn AsLoadConfigV9 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV9")
            .field("guard_eh_continuation_table", &self.guard_eh_continuation_table())
            .field("guard_eh_continuation_count", &self.guard_eh_continuation_count())
            .finish()
    }
}


impl<'a> FromFFI<ffi::PE_LoadConfigurationV9> for LoadConfigV9<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV9>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsLoadConfigV9 {
    #[doc(hidden)]
    fn as_v9(&self) -> &ffi::PE_LoadConfigurationV9;

    fn guard_eh_continuation_table(&self) -> u64 {
        self.as_v9().guard_eh_continuation_table()
    }

    fn guard_eh_continuation_count(&self) -> u64 {
        self.as_v9().guard_eh_continuation_count()
    }
}

impl AsBase for LoadConfigV9<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV9<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV9<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV9<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV3 for LoadConfigV9<'_> {
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV4 for LoadConfigV9<'_> {
    fn as_v4(&self) -> &ffi::PE_LoadConfigurationV4 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV5 for LoadConfigV9<'_> {
    fn as_v5(&self) -> &ffi::PE_LoadConfigurationV5 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV6 for LoadConfigV9<'_> {
    fn as_v6(&self) -> &ffi::PE_LoadConfigurationV6 {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV7 for LoadConfigV9<'_> {
    fn as_v7(&self) -> &ffi::PE_LoadConfigurationV7 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV8 for LoadConfigV9<'_> {
    fn as_v8(&self) -> &ffi::PE_LoadConfigurationV8 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV9 for LoadConfigV9<'_> {
    fn as_v9(&self) -> &ffi::PE_LoadConfigurationV9 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV10<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV10>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for LoadConfigV10<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV10;
        f.write_str(format!("{base:?}").as_str())
    }
}

impl std::fmt::Debug for &dyn AsLoadConfigV10 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV10")
            .field("guard_xfg_check_function_pointer", &self.guard_xfg_check_function_pointer())
            .field("guard_xfg_dispatch_function_pointer", &self.guard_xfg_dispatch_function_pointer())
            .field("guard_xfg_table_dispatch_function_pointer", &self.guard_xfg_table_dispatch_function_pointer())
            .finish()
    }
}


impl<'a> FromFFI<ffi::PE_LoadConfigurationV10> for LoadConfigV10<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV10>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsLoadConfigV10 {
    #[doc(hidden)]
    fn as_v10(&self) -> &ffi::PE_LoadConfigurationV10;

    fn guard_xfg_check_function_pointer(&self) -> u64 {
        self.as_v10().guard_xfg_check_function_pointer()
    }

    fn guard_xfg_dispatch_function_pointer(&self) -> u64 {
        self.as_v10().guard_xfg_dispatch_function_pointer()
    }

    fn guard_xfg_table_dispatch_function_pointer(&self) -> u64 {
        self.as_v10().guard_xfg_table_dispatch_function_pointer()
    }
}

impl AsBase for LoadConfigV10<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV10<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV10<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV10<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV3 for LoadConfigV10<'_> {
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV4 for LoadConfigV10<'_> {
    fn as_v4(&self) -> &ffi::PE_LoadConfigurationV4 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV5 for LoadConfigV10<'_> {
    fn as_v5(&self) -> &ffi::PE_LoadConfigurationV5 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV6 for LoadConfigV10<'_> {
    fn as_v6(&self) -> &ffi::PE_LoadConfigurationV6 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV7 for LoadConfigV10<'_> {
    fn as_v7(&self) -> &ffi::PE_LoadConfigurationV7 {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV8 for LoadConfigV10<'_> {
    fn as_v8(&self) -> &ffi::PE_LoadConfigurationV8 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV9 for LoadConfigV10<'_> {
    fn as_v9(&self) -> &ffi::PE_LoadConfigurationV9 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV10 for LoadConfigV10<'_> {
    fn as_v10(&self) -> &ffi::PE_LoadConfigurationV10 {
        self.ptr.as_ref().unwrap()
    }
}

pub struct LoadConfigV11<'a> {
    ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV11>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for LoadConfigV11<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn AsLoadConfigV11;
        f.write_str(format!("{base:?}").as_str())
    }
}

impl std::fmt::Debug for &dyn AsLoadConfigV11 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadConfigV11")
            .field("cast_guard_os_determined_failure_mode", &self.cast_guard_os_determined_failure_mode())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_LoadConfigurationV11> for LoadConfigV11<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_LoadConfigurationV11>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub trait AsLoadConfigV11 {
    #[doc(hidden)]
    fn as_v11(&self) -> &ffi::PE_LoadConfigurationV11;

    fn cast_guard_os_determined_failure_mode(&self) -> u64 {
        self.as_v11().cast_guard_os_determined_failure_mode()
    }
}

impl AsBase for LoadConfigV11<'_> {
    fn as_base(&self) -> &ffi::PE_LoadConfiguration {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV0 for LoadConfigV11<'_> {
    fn as_v0(&self) -> &ffi::PE_LoadConfigurationV0 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV1 for LoadConfigV11<'_> {
    fn as_v1(&self) -> &ffi::PE_LoadConfigurationV1 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV2 for LoadConfigV11<'_> {
    fn as_v2(&self) -> &ffi::PE_LoadConfigurationV2 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV3 for LoadConfigV11<'_> {
    fn as_v3(&self) -> &ffi::PE_LoadConfigurationV3 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV4 for LoadConfigV11<'_> {
    fn as_v4(&self) -> &ffi::PE_LoadConfigurationV4 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV5 for LoadConfigV11<'_> {
    fn as_v5(&self) -> &ffi::PE_LoadConfigurationV5 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV6 for LoadConfigV11<'_> {
    fn as_v6(&self) -> &ffi::PE_LoadConfigurationV6 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV7 for LoadConfigV11<'_> {
    fn as_v7(&self) -> &ffi::PE_LoadConfigurationV7 {
        self.ptr
            .as_ref()
            .unwrap()
            .as_ref()
            .as_ref()
            .as_ref()
            .as_ref()
    }
}

impl AsLoadConfigV8 for LoadConfigV11<'_> {
    fn as_v8(&self) -> &ffi::PE_LoadConfigurationV8 {
        self.ptr.as_ref().unwrap().as_ref().as_ref().as_ref()
    }
}

impl AsLoadConfigV9 for LoadConfigV11<'_> {
    fn as_v9(&self) -> &ffi::PE_LoadConfigurationV9 {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

impl AsLoadConfigV10 for LoadConfigV11<'_> {
    fn as_v10(&self) -> &ffi::PE_LoadConfigurationV10 {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl AsLoadConfigV11 for LoadConfigV11<'_> {
    fn as_v11(&self) -> &ffi::PE_LoadConfigurationV11 {
        self.ptr.as_ref().unwrap()
    }
}
