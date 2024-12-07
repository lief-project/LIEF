use lief_ffi as ffi;

use crate::Error;
use crate::common::{FromFFI, into_optional};
use crate::{declare_iterator, declare_fwd_iterator, to_result};
use super::{SubCache, Dylib, MappingInfo};

use crate::assembly;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// This enum wraps the dyld's git tags for which the structure of
/// dyld shared cache evolved
pub enum Version {
    /// dyld-95.3 (2007-10-30)
    DYLD_95_3,
    /// dyld-195.5 (2011-07-13)
    DYLD_195_5,
    /// dyld-239.3 (2013-10-29)
    DYLD_239_3,
    /// dyld-360.14 (2015-09-04)
    DYLD_360_14,
    /// dyld-421.1 (2016-09-22)
    DYLD_421_1,
    /// dyld-832.7.1 (2020-11-19)
    DYLD_832_7_1,
    /// dyld-940 (2021-02-09)
    DYLD_940,
    /// dyld-1042.1 (2022-10-19)
    DYLD_1042_1,
    /// This value is used for versions of dyld not publicly released or not yet
    /// supported by LIEF
    UNRELEASED,
    UNKNOWN(u32),
}

impl From<u32> for Version {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Version::DYLD_95_3,
            0x00000002 => Version::DYLD_195_5,
            0x00000003 => Version::DYLD_239_3,
            0x00000004 => Version::DYLD_360_14,
            0x00000005 => Version::DYLD_421_1,
            0x00000006 => Version::DYLD_832_7_1,
            0x00000007 => Version::DYLD_940,
            0x00000008 => Version::DYLD_1042_1,
            0x00000009 => Version::UNRELEASED,
            _ => Version::UNKNOWN(value),

        }
    }
}
impl From<Version> for u32 {
    fn from(value: Version) -> u32 {
        match value {
            Version::DYLD_95_3    => 0x00000001,
            Version::DYLD_195_5   => 0x00000002,
            Version::DYLD_239_3   => 0x00000003,
            Version::DYLD_360_14  => 0x00000004,
            Version::DYLD_421_1   => 0x00000005,
            Version::DYLD_832_7_1 => 0x00000006,
            Version::DYLD_940     => 0x00000007,
            Version::DYLD_1042_1  => 0x00000008,
            Version::UNRELEASED   => 0x00000009,
            Version::UNKNOWN(_) => 0,

        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// Platforms supported by the dyld shared cache
pub enum Platform {
    MACOS,
    IOS,
    TVOS,
    WATCHOS,
    BRIDGEOS,
    IOSMAC,
    IOS_SIMULATOR,
    TVOS_SIMULATOR,
    WATCHOS_SIMULATOR,
    DRIVERKIT,
    VISIONOS,
    VISIONOS_SIMULATOR,
    FIRMWARE,
    SEPOS,
    ANY,
    UNKNOWN(u32),
}

impl From<u32> for Platform {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Platform::MACOS,
            0x00000002 => Platform::IOS,
            0x00000003 => Platform::TVOS,
            0x00000004 => Platform::WATCHOS,
            0x00000005 => Platform::BRIDGEOS,
            0x00000006 => Platform::IOSMAC,
            0x00000007 => Platform::IOS_SIMULATOR,
            0x00000008 => Platform::TVOS_SIMULATOR,
            0x00000009 => Platform::WATCHOS_SIMULATOR,
            0x0000000a => Platform::DRIVERKIT,
            0x0000000b => Platform::VISIONOS,
            0x0000000c => Platform::VISIONOS_SIMULATOR,
            0x0000000d => Platform::FIRMWARE,
            0x0000000e => Platform::SEPOS,
            0xffffffff => Platform::ANY,
            _ => Platform::UNKNOWN(value),

        }
    }
}
impl From<Platform> for u32 {
    fn from(value: Platform) -> u32 {
        match value {
            Platform::MACOS => 0x00000001,
            Platform::IOS => 0x00000002,
            Platform::TVOS => 0x00000003,
            Platform::WATCHOS => 0x00000004,
            Platform::BRIDGEOS => 0x00000005,
            Platform::IOSMAC => 0x00000006,
            Platform::IOS_SIMULATOR => 0x00000007,
            Platform::TVOS_SIMULATOR => 0x00000008,
            Platform::WATCHOS_SIMULATOR => 0x00000009,
            Platform::DRIVERKIT => 0x0000000a,
            Platform::VISIONOS => 0x0000000b,
            Platform::VISIONOS_SIMULATOR => 0x0000000c,
            Platform::FIRMWARE => 0x0000000d,
            Platform::SEPOS => 0x0000000e,
            Platform::ANY => 0xffffffff,
            Platform::UNKNOWN(_) => 0,

        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// Architecture supported by the dyld shared cache
pub enum Arch {
    I386,
    X86_64,
    X86_64H,
    ARMV5,
    ARMV6,
    ARMV7,
    ARM64,
    ARM64E,
    UNKNOWN(u32),
}

impl From<u32> for Arch {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Arch::I386,
            0x00000002 => Arch::X86_64,
            0x00000003 => Arch::X86_64H,
            0x00000004 => Arch::ARMV5,
            0x00000005 => Arch::ARMV6,
            0x00000006 => Arch::ARMV7,
            0x00000007 => Arch::ARM64,
            0x00000008 => Arch::ARM64E,
            _ => Arch::UNKNOWN(value),

        }
    }
}
impl From<Arch> for u32 {
    fn from(value: Arch) -> u32 {
        match value {
            Arch::I386 => 0x00000001,
            Arch::X86_64 => 0x00000002,
            Arch::X86_64H => 0x00000003,
            Arch::ARMV5 => 0x00000004,
            Arch::ARMV6 => 0x00000005,
            Arch::ARMV7 => 0x00000006,
            Arch::ARM64 => 0x00000007,
            Arch::ARM64E => 0x00000008,
            Arch::UNKNOWN(_) => 0,

        }
    }
}

/// This struct interfaces a dyld shared cache file.
pub struct DyldSharedCache {
    ptr: cxx::UniquePtr<ffi::dsc_DyldSharedCache>,
}

impl FromFFI<ffi::dsc_DyldSharedCache> for DyldSharedCache {
    fn from_ffi(info: cxx::UniquePtr<ffi::dsc_DyldSharedCache>) -> Self {
        Self {
            ptr: info,
        }
    }
}

impl DyldSharedCache {
    /// Filename of the dyld shared file associated with this object.
    ///
    /// For instance: `dyld_shared_cache_arm64e, dyld_shared_cache_arm64e.62.dyldlinkedit`
    pub fn filename(&self) -> String {
        self.ptr.filename().to_string()
    }

    /// Full path to the original dyld shared cache file associated with object
    /// (e.g. `/home/lief/downloads/visionos/dyld_shared_cache_arm64e.42`)
    pub fn filepath(&self) -> String {
        self.ptr.filepath().to_string()
    }

    /// Based address of this cache
    pub fn load_address(&self) -> u64 {
        self.ptr.load_address()
    }

    /// Version of dyld used by this cache
    pub fn version(&self) -> Version {
        Version::from(self.ptr.version())
    }

    /// Name of the architecture targeted by this cache (`x86_64h`)
    pub fn arch_name(&self) -> String {
        self.ptr.arch_name().to_string()
    }

    /// Platform targeted by this cache (e.g. vision-os)
    pub fn platform(&self) -> Platform {
        Platform::from(self.ptr.platform())
    }

    /// Architecture targeted by this cache
    pub fn arch(&self) -> Arch {
        Arch::from(self.ptr.arch())
    }

    /// Find the [`Dylib`] that encompasses the given virtual address.
    pub fn find_lib_from_va(&self, va: u64) -> Option<Dylib> {
        into_optional(self.ptr.find_lib_from_va(va))
    }

    /// Find the [`Dylib`] whose [`Dylib::path`] matches the provided path.
    pub fn find_lib_from_path(&self, path: &str) -> Option<Dylib> {
        into_optional(self.ptr.find_lib_from_path(path))
    }

    /// Find the [`Dylib`] whose filename of [`Dylib::path`] matches the provided name.
    ///
    /// If multiple libraries have the same name (but with a different path),
    /// the **first one** matching the provided name is returned.
    pub fn find_lib_from_name(&self, name: &str) -> Option<Dylib> {
        into_optional(self.ptr.find_lib_from_name(name))
    }

    /// True if the subcaches are associated with this cache
    pub fn has_subcaches(&self) -> bool {
        self.ptr.has_subcaches()
    }

    /// Return an iterator over the different [`Dylib`] libraries embedded
    /// in this dyld shared cache
    pub fn libraries(&self) -> Dylibs {
        Dylibs::new(self.ptr.libraries())
    }

    /// Return an iterator over the different [`MappingInfo`] associated
    /// with this dyld shared cache
    pub fn mapping_info(&self) -> MappingInfoIt {
        MappingInfoIt::new(self.ptr.mapping_info())
    }

    /// Return an interator over the subcaches associated with this (main) dyld shared
    /// cache.
    pub fn subcaches(&self) -> SubCacheIt {
        SubCacheIt::new(self.ptr.subcaches())
    }

    /// Disassemble instructions at the provided virtual address.
    ///
    /// This function returns an iterator over [`assembly::Instructions`].
    pub fn disassemble(&self, address: u64) -> Instructions {
        Instructions::new(self.ptr.disassemble(address))
    }

    /// Return the content at the specified virtual address
    pub fn get_content_from_va(&self, address: u64, size: u64) -> Vec<u8> {
        Vec::from(self.ptr.get_content_from_va(address, size).as_slice())
    }

    /// Find the sub-DyldSharedCache that wraps the given virtual address
    pub fn cache_for_address(&self, address: u64) -> Option<DyldSharedCache> {
        into_optional(self.ptr.cache_for_address(address))
    }

    /// Return the principal dyld shared cache in the case of multiple subcaches
    pub fn main_cache(&self) -> Option<DyldSharedCache> {
        into_optional(self.ptr.main_cache())
    }

    /// Try to find the [`DyldSharedCache`] associated with the filename given
    /// in the first parameter.
    pub fn find_subcache(&self, filename: &str) -> Option<DyldSharedCache> {
        into_optional(self.ptr.find_subcache(filename))
    }

    /// Convert the given virtual address into an offset.
    /// <div class="warning">
    /// If the shared cache contains multiple subcaches,
    /// this function needs to be called on the targeted subcache.
    /// </div>
    ///
    /// See: [`DyldSharedCache::cache_for_address`]
    pub fn va_to_offset(&self, address: u64) -> Result<u64, Error> {
        to_result!(ffi::dsc_DyldSharedCache::va_to_offset, &self, address);
    }

    /// When enabled, this function allows to record and to keep in *cache*,
    /// dyld shared cache information that are costly to access.
    ///
    /// For instance, GOT symbols, rebases information, stub symbols, ...
    ///
    /// It is **highly** recommended to enable this function when processing
    /// a dyld shared cache several times or when extracting a large number of
    /// [`Dylib`] with enhanced extraction options (e.g. [`crate::dsc::dylib::ExtractOpt::fix_memory`])
    ///
    /// One can enable caching by calling this function:
    ///
    /// ```rust
    /// let dyld_cache = lief::dsc::load_from_path("macos-15.0.1/", "");
    /// dyld_cache.enable_caching("/home/user/.cache/lief-dsc");
    /// ```
    ///
    /// One can also enable this cache optimization **globally** using the
    /// function: [`crate::dsc::enable_cache`] or by setting the environment variable
    /// `DYLDSC_ENABLE_CACHE` to 1.
    pub fn enable_caching(&self, target_cache_dir: &str) {
        self.ptr.enable_caching(target_cache_dir)
    }

    /// Flush internal information into the on-disk cache (see: enable_caching)
    pub fn flush_cache(&self) {
        self.ptr.flush_cache()
    }
}

declare_iterator!(
    Dylibs,
    Dylib<'a>,
    ffi::dsc_Dylib,
    ffi::dsc_DyldSharedCache,
    ffi::dsc_DyldSharedCache_it_libraries
);

declare_iterator!(
    MappingInfoIt,
    MappingInfo<'a>,
    ffi::dsc_MappingInfo,
    ffi::dsc_DyldSharedCache,
    ffi::dsc_DyldSharedCache_it_mapping_info
);

declare_iterator!(
    SubCacheIt,
    SubCache<'a>,
    ffi::dsc_SubCache,
    ffi::dsc_DyldSharedCache,
    ffi::dsc_DyldSharedCache_it_subcaches
);

declare_fwd_iterator!(
    Instructions,
    assembly::Instructions,
    ffi::asm_Instruction,
    ffi::dsc_DyldSharedCache,
    ffi::dsc_DyldSharedCache_it_instructions
);
