//! Module for Dyld shared cache support
//!
//! ### Getting Started
//!
//! ```rust
//! let dyld_cache = lief::dsc::from_path("macos-15.0.1/");
//! for dylib in dyld_cache.libraries() {
//!     println!("0x{:016x}: {}", dylib.address(), dylib.path());
//!     let macho: lief::macho::Binary = dylib.get().expect("Can't get Mach-O representation");
//! }
//! ```
//!
//! ### Performance Considerations
//!
//! <div class="warning">
//! If you aim at extracting several libraries from a dyld shared cache, it is
//! <b>highly</b> recommended to enable caching. Otherwise, performances can be
//! impacted.
//! </div>
//!
//! See: [`crate::dsc::enable_cache`] and [`crate::dsc::enable_cache_from_dir`]
use lief_ffi as ffi;
use std::ffi::{CString, c_char};
use crate::common::into_optional;

pub mod dyld_shared_cache;
pub mod mapping_info;
pub mod subcache;
pub mod dylib;
pub mod uuid;

mod caching;

#[doc(inline)]
pub use dyld_shared_cache::DyldSharedCache;

#[doc(inline)]
pub use dylib::Dylib;

#[doc(inline)]
pub use subcache::SubCache;

#[doc(inline)]
pub use mapping_info::MappingInfo;

#[doc(inline)]
pub use uuid::UUID;

#[doc(inline)]
pub use caching::enable_cache;

#[doc(inline)]
pub use caching::enable_cache_from_dir;


/// Load a shared cache from a single file or from a directory specified
/// by the `path` parameter.
///
/// In the case where multiple architectures are
/// available in the `path` directory, the `arch` parameter can be used to
/// define which architecture should be prefered.
///
/// **Example:**
///
/// ```rust
/// // From a directory (split caches)
/// let cache = lief::dsc::load("vision-pro-2.0/", "");
///
/// // From a single cache file
/// let cache = lief::dsc::load("ios-14.2/dyld_shared_cache_arm64", "");
///
/// // From a directory with multiple architectures
/// let cache = LIEF::dsc::load("macos-12.6/", /*arch=*/"x86_64h");
/// ```
pub fn load_from_path(path: &str, arch: &str) -> Option<DyldSharedCache> {
    into_optional(ffi::dsc_DyldSharedCache::from_path(path, arch))
}

pub fn load_from_files(files: &[String]) -> Option<DyldSharedCache> {
    let mut c_strings = Vec::new();
    let mut c_ptrs = Vec::new();
    for file in files.iter() {
        let c_str = CString::new(file.as_str()).unwrap();
        c_strings.push(c_str);
        let c_ptr = c_strings.last().unwrap().as_ptr() as *const c_char;
        c_ptrs.push(c_ptr);
    }
    let files_ptr: *const *const c_char = c_ptrs.as_ptr();
    unsafe {
        into_optional(ffi::dsc_DyldSharedCache::from_files(files_ptr as *const c_char, c_ptrs.len()))
    }
}
