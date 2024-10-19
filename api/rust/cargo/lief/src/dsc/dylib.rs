use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use std::marker::PhantomData;
use crate::macho::Binary;

/// This structure represents a library embedded in a dyld shared cache.
/// It mirrors the original `dyld_cache_image_info` structure.
pub struct Dylib<'a> {
    ptr: cxx::UniquePtr<ffi::dsc_Dylib>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::dsc_Dylib> for Dylib<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::dsc_Dylib>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Dylib<'_> {
    /// Original path of the library (e.g. `/usr/lib/libcryptex.dylib`)
    pub fn path(&self) -> String {
        self.ptr.path().to_string()
    }

    /// In-memory address of the library
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }

    /// Modification time of the library matching `stat.st_mtime`, or 0
    pub fn modtime(&self) -> u64 {
        self.ptr.modtime()
    }

    /// File serial number matching `stat.st_ino` or 0
    ///
    /// Note that for shared cache targeting iOS, this value can hold a hash of
    /// the path (if modtime is set to 0)
    pub fn inode(&self) -> u64 {
        self.ptr.inode()
    }

    /// Padding alignment value (should be 0)
    pub fn padding(&self) -> u64 {
        self.ptr.padding()
    }

    /// Get a [`Binary`] representation for this Dylib.
    ///
    /// One can use this function to write back the Mach-O binary on the disk:
    ///
    /// ```cpp
    /// dylib.get().expect("Can't extract").write("liblockdown.dylib");
    /// ```
    pub fn get(&self) -> Option<Binary> {
        self.get_with_opt(&ExtractOpt::default())
    }
    /// Get a [`Binary`] representation for this Dylib with the provided [`ExtractOpt`] options.
    pub fn get_with_opt(&self, opt: &ExtractOpt) -> Option<Binary> {
        into_optional(self.ptr.get_macho(opt.to_ffi()))
    }
}

/// This structure is used to tweak the extraction process while calling
/// [`Dylib::get_with_opt`]. These options allow to deoptimize the dylib and get an
/// accurate representation of the origin Mach-O binary.
pub struct ExtractOpt {
    /// Whether the segment's offsets should be packed to avoid
    /// an in-memory size while writing back the binary.
    ///
    /// <div class="note">This option does not have an impact on the performances</div>
    pub pack: bool,

    /// Fix call instructions that target addresses outside the current dylib
    /// virtual space.
    ///
    /// <div class="warning">
    /// Enabling this option can have a significant impact on the performances.
    /// Make sure to enable the internal cache mechanism.
    /// </div>
    ///
    /// [`crate::dsc::enable_cache`] or [`crate::dsc::DyldSharedCache::enable_caching`]
    pub fix_branches: bool,

    /// Fix memory accesses performed outside the dylib's virtual space
    ///
    /// <div class="warning">
    /// Enabling this option can have a significant impact on the performances.
    /// Make sure to enable the internal cache mechanism.
    /// </div>
    ///
    /// [`crate::dsc::enable_cache`] or [`crate::dsc::DyldSharedCache::enable_caching`]
    pub fix_memory: bool,

    /// Recover and fix relocations
    ///
    /// <div class="warning">
    /// Enabling this option can have a significant impact on the performances.
    /// Make sure to enable the internal cache mechanism.
    /// </div>
    ///
    /// [`crate::dsc::enable_cache`] or [`crate::dsc::DyldSharedCache::enable_caching`]
    pub fix_relocations: bool,

    /// Fix Objective-C information
    ///
    /// <div class="warning">
    /// Enabling this option can have a significant impact on the performances.
    /// Make sure to enable the internal cache mechanism.
    /// </div>
    ///
    /// [`crate::dsc::enable_cache`] or [`crate::dsc::DyldSharedCache::enable_caching`]
    pub fix_objc: bool,

    /// Whether the `LC_DYLD_CHAINED_FIXUPS` command should be (re)created.
    ///
    /// If this value is not set, LIEF will add the command only if it's
    /// meaningful regarding the other options
    pub create_dyld_chained_fixup_cmd: Option<bool>,
}

impl Default for ExtractOpt {
    fn default() -> ExtractOpt {
        ExtractOpt {
            pack: true,
            fix_branches: false,
            fix_memory: true,
            fix_relocations: true,
            fix_objc: true,
            create_dyld_chained_fixup_cmd: None,
        }
    }
}

impl ExtractOpt {
    #[doc(hidden)]
    fn to_ffi(&self) -> ffi::dsc_Dylib_extract_opt {
        ffi::dsc_Dylib_extract_opt {
            pack: self.pack,
            fix_branches: self.fix_branches,
            fix_memory: self.fix_memory,
            fix_relocations: self.fix_relocations,
            fix_objc: self.fix_objc,
            create_dyld_chained_fixup_cmd: self.create_dyld_chained_fixup_cmd.unwrap_or(false),
            create_dyld_chained_fixup_cmd_set: self.create_dyld_chained_fixup_cmd.is_some()
        }
    }
}

impl std::fmt::Debug for Dylib<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dylib")
            .field("path", &self.path())
            .field("address", &self.address())
            .field("modtime", &self.modtime())
            .field("inode", &self.inode())
            .field("padding", &self.padding())
            .finish()

    }
}
