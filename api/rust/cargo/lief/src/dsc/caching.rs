use lief_ffi as ffi;

/// Enable globally cache/memoization. One can also leverage this function
/// by setting the environment variable `DYLDSC_ENABLE_CACHE` to `1`
///
/// By default, LIEF will use the directory specified by the environment
/// variable `DYLDSC_CACHE_DIR` as its cache-root directory:
///
/// ```bash
/// DYLDSC_ENABLE_CACHE=1 DYLDSC_CACHE_DIR=/tmp/my_dir ./my-program
/// ```
///
/// Otherwise, if `DYLDSC_CACHE_DIR` is not set, LIEF will use the following
/// directory (in this priority):
///
/// 1. System or user cache directory
///   - macOS: `DARWIN_USER_TEMP_DIR` / `DARWIN_USER_CACHE_DIR` + `/dyld_shared_cache`
///   - Linux: `${XDG_CACHE_HOME}/dyld_shared_cache`
///   - Windows: `%LOCALAPPDATA%\dyld_shared_cache`
/// 2. Home directory
///   - macOS/Linux: `$HOME/.dyld_shared_cache`
///   - Windows: `%USERPROFILE%\.dyld_shared_cache`
///
/// See [`crate::dsc::DyldSharedCache::enable_caching`] for a finer granularity
pub fn enable_cache() -> bool {
    ffi::dsc_enable_cache()
}

/// Same behavior as [`enable_cache`] but with a user-provided cache directory
pub fn enable_cache_from_dir(target_dir: &str) -> bool {
    ffi::dsc_enable_cache_from_dir(target_dir)
}
