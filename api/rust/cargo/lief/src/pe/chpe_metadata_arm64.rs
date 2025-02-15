use super::load_configuration::AsCHPEMetadata;
use crate::common::FromFFI;
use crate::declare_iterator;
use lief_ffi as ffi;
use std::marker::PhantomData;

/// This structure represents hybrid metadata for ARM64EC or ARM64X.
pub struct CHPEMetadata<'a> {
    ptr: cxx::UniquePtr<ffi::PE_CHPEMetadataARM64>,
    _owner: PhantomData<&'a ffi::PE_LoadConfiguration>,
}

impl<'a> FromFFI<ffi::PE_CHPEMetadataARM64> for CHPEMetadata<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_CHPEMetadataARM64>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl CHPEMetadata<'_> {
    /// RVA to the array that describes architecture-specific ranges
    pub fn code_map(&self) -> u32 {
        self.ptr.code_map()
    }

    /// Number of entries in the code map
    pub fn code_map_count(&self) -> u32 {
        self.ptr.code_map_count()
    }

    pub fn redirection_metadata(&self) -> u32 {
        self.ptr.redirection_metadata()
    }

    pub fn os_arm64x_dispatch_call_no_redirect(&self) -> u32 {
        self.ptr.os_arm64x_dispatch_call_no_redirect()
    }

    pub fn os_arm64x_dispatch_ret(&self) -> u32 {
        self.ptr.os_arm64x_dispatch_ret()
    }

    pub fn os_arm64x_dispatch_call(&self) -> u32 {
        self.ptr.os_arm64x_dispatch_call()
    }

    pub fn os_arm64x_dispatch_icall(&self) -> u32 {
        self.ptr.os_arm64x_dispatch_icall()
    }

    pub fn os_arm64x_dispatch_icall_cfg(&self) -> u32 {
        self.ptr.os_arm64x_dispatch_icall_cfg()
    }

    pub fn alternate_entry_point(&self) -> u32 {
        self.ptr.alternate_entry_point()
    }

    pub fn auxiliary_iat(&self) -> u32 {
        self.ptr.auxiliary_iat()
    }

    pub fn code_ranges_to_entry_points_count(&self) -> u32 {
        self.ptr.code_ranges_to_entry_points_count()
    }

    pub fn redirection_metadata_count(&self) -> u32 {
        self.ptr.redirection_metadata_count()
    }

    pub fn get_x64_information_function_pointer(&self) -> u32 {
        self.ptr.get_x64_information_function_pointer()
    }

    pub fn set_x64_information_function_pointer(&self) -> u32 {
        self.ptr.set_x64_information_function_pointer()
    }

    /// RVA to this architecture-specific exception table
    pub fn extra_rfe_table(&self) -> u32 {
        self.ptr.extra_rfe_table()
    }

    /// Architecture-specific exception table size
    pub fn extra_rfe_table_size(&self) -> u32 {
        self.ptr.extra_rfe_table_size()
    }

    pub fn auxiliary_iat_copy(&self) -> u32 {
        self.ptr.auxiliary_iat_copy()
    }

    pub fn auxiliary_delay_import(&self) -> u32 {
        self.ptr.auxiliary_delay_import()
    }

    pub fn auxiliary_delay_import_copy(&self) -> u32 {
        self.ptr.auxiliary_delay_import_copy()
    }

    pub fn bitfield_info(&self) -> u32 {
        self.ptr.bitfield_info()
    }

    pub fn code_ranges(&self) -> CodeRanges {
        CodeRanges::new(self.ptr.code_ranges())
    }

    pub fn redirections(&self) -> Redirections {
        Redirections::new(self.ptr.redirections())
    }
}

impl AsCHPEMetadata for CHPEMetadata<'_> {
    fn as_generic(&self) -> &ffi::PE_CHPEMetadata {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for CHPEMetadata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CHPEMetadataARM64")
            .field("code_map", &self.code_map())
            .field("code_map_count", &self.code_map_count())
            .field("redirection_metadata", &self.redirection_metadata())
            .field(
                "os_arm64x_dispatch_call_no_redirect",
                &self.os_arm64x_dispatch_call_no_redirect(),
            )
            .field("os_arm64x_dispatch_ret", &self.os_arm64x_dispatch_ret())
            .field("os_arm64x_dispatch_call", &self.os_arm64x_dispatch_call())
            .field("os_arm64x_dispatch_icall", &self.os_arm64x_dispatch_icall())
            .field(
                "os_arm64x_dispatch_icall_cfg",
                &self.os_arm64x_dispatch_icall_cfg(),
            )
            .field("alternate_entry_point", &self.alternate_entry_point())
            .field("auxiliary_iat", &self.auxiliary_iat())
            .field(
                "code_ranges_to_entry_points_count",
                &self.code_ranges_to_entry_points_count(),
            )
            .field(
                "redirection_metadata_count",
                &self.redirection_metadata_count(),
            )
            .field(
                "get_x64_information_function_pointer",
                &self.get_x64_information_function_pointer(),
            )
            .field(
                "set_x64_information_function_pointer",
                &self.set_x64_information_function_pointer(),
            )
            .field("extra_rfe_table", &self.extra_rfe_table())
            .field("extra_rfe_table_size", &self.extra_rfe_table_size())
            .field("auxiliary_iat_copy", &self.auxiliary_iat_copy())
            .field("auxiliary_delay_import", &self.auxiliary_delay_import())
            .field(
                "auxiliary_delay_import_copy",
                &self.auxiliary_delay_import_copy(),
            )
            .field("bitfield_info", &self.bitfield_info())
            .finish()
    }
}

/// Structure that describes architecture-specific ranges
pub struct RangeEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_CHPEMetadataARM64_range_entry_t>,
    _owner: PhantomData<&'a ffi::PE_LoadConfiguration>,
}

impl<'a> FromFFI<ffi::PE_CHPEMetadataARM64_range_entry_t> for RangeEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_CHPEMetadataARM64_range_entry_t>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RangeType {
    ARM64,
    ARM64EC,
    AMD64,
    UNKNOWN(u32),
}

impl From<u32> for RangeType {
    fn from(value: u32) -> Self {
        match value {
            0x000000000 => RangeType::ARM64,
            0x000000001 => RangeType::ARM64EC,
            0x000000002 => RangeType::AMD64,
            _ => RangeType::UNKNOWN(value),
        }
    }
}

impl RangeEntry<'_> {
    /// Raw data (include start RVA and type)
    pub fn start_offset(&self) -> u32 {
        self.ptr.start_offset()
    }

    /// Range's length
    pub fn length(&self) -> u32 {
        self.ptr.length()
    }

    /// Start of the range (RVA)
    pub fn start(&self) -> u32 {
        self.ptr.start()
    }

    /// End of the range (RVA)
    pub fn end(&self) -> u32 {
        self.ptr.end()
    }

    /// Architecture for this range
    pub fn range_type(&self) -> RangeType {
        RangeType::from(self.ptr.get_type())
    }
}

impl std::fmt::Debug for RangeEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeEntry")
            .field("start_offset", &self.start_offset())
            .field("length", &self.length())
            .field("start", &self.start())
            .field("end", &self.end())
            .field("range_type", &self.range_type())
            .finish()
    }
}

/// Structure that describes a redirection
pub struct RedirectionEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_CHPEMetadataARM64_redirection_entry_t>,
    _owner: PhantomData<&'a ffi::PE_LoadConfiguration>,
}

impl<'a> FromFFI<ffi::PE_CHPEMetadataARM64_redirection_entry_t> for RedirectionEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_CHPEMetadataARM64_redirection_entry_t>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl RedirectionEntry<'_> {
    pub fn src(&self) -> u32 {
        self.ptr.src()
    }

    pub fn dst(&self) -> u32 {
        self.ptr.dst()
    }
}

impl std::fmt::Debug for RedirectionEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedirectionEntry")
            .field("src", &self.src())
            .field("dst", &self.dst())
            .finish()
    }
}

declare_iterator!(
    CodeRanges,
    RangeEntry<'a>,
    ffi::PE_CHPEMetadataARM64_range_entry_t,
    ffi::PE_CHPEMetadataARM64,
    ffi::PE_CHPEMetadataARM64_it_const_range_entries
);

declare_iterator!(
    Redirections,
    RedirectionEntry<'a>,
    ffi::PE_CHPEMetadataARM64_redirection_entry_t,
    ffi::PE_CHPEMetadataARM64,
    ffi::PE_CHPEMetadataARM64_it_const_redirection_entries
);
