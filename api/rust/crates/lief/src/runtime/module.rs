use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use crate::declare_standalone_fwd_iterator;
use std::path::Path;

use super::android;
use super::linux;
use super::osx;
use super::windows;

/// This trait is shared by all system-specific modules.
/// It provides a common interface for accessing module metadata.
pub trait Module {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::runtime_Module;

    /// Name of the module (e.g. `libc.so.6, kernel32.dll, libsystem_c.dylib`)
    fn name(&self) -> String {
        self.as_generic().name().to_string()
    }

    /// Absolute path to the module file
    fn path(&self) -> String {
        self.as_generic().path().to_string()
    }

    /// Base address where the module is loaded in memory
    fn imagebase(&self) -> u64 {
        self.as_generic().imagebase()
    }

    /// Virtual size of the current module
    fn size(&self) -> u64 {
        self.as_generic().size()
    }

    /// End address of the module
    fn end(&self) -> u64 {
        self.as_generic().end()
    }

    /// Check if the current module contains the given address
    fn contains(&self, addr: u64) -> bool {
        self.as_generic().contains(addr)
    }

    /// Return the content of the module as it is currently mapped in memory.
    ///
    /// The returned buffer spans [`Module::imagebase`] over [`Module::size`]
    /// bytes. An empty buffer is returned if the imagebase or the size is null.
    fn dump(&self) -> Vec<u8> {
        let base = self.imagebase();
        let size = self.size() as usize;
        if base == 0 || size == 0 {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(base as *const u8, size).to_vec() }
    }

    /// Same as [`Module::dump`] but also write the content into the file
    /// located at `path`.
    fn dump_to_file<P: AsRef<Path>>(&self, path: P) -> Vec<u8> {
        let data = self.dump();
        let _ = std::fs::write(path, &data);
        data
    }
}

/// Enum for the modules whose value depends on the current platform
pub enum Modules {
    /// A Linux module
    Linux(linux::Module),

    /// A Windows module
    Windows(windows::Module),

    /// An Android module
    Android(android::Module),

    /// An OSX module
    Osx(osx::Module),
}

impl FromFFI<ffi::runtime_Module> for Modules {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::runtime_Module>) -> Self {
        unsafe {
            let mod_ref = ptr.as_ref().unwrap();
            if ffi::runtime_linux_Module::classof(mod_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::runtime_Module>;
                    type To = cxx::UniquePtr<ffi::runtime_linux_Module>;
                    std::mem::transmute::<From, To>(ptr)
                };
                return Modules::Linux(linux::Module::from_ffi(raw));
            } else if ffi::runtime_windows_Module::classof(mod_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::runtime_Module>;
                    type To = cxx::UniquePtr<ffi::runtime_windows_Module>;
                    std::mem::transmute::<From, To>(ptr)
                };
                return Modules::Windows(windows::Module::from_ffi(raw));
            } else if ffi::runtime_android_Module::classof(mod_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::runtime_Module>;
                    type To = cxx::UniquePtr<ffi::runtime_android_Module>;
                    std::mem::transmute::<From, To>(ptr)
                };
                return Modules::Android(android::Module::from_ffi(raw));
            } else if ffi::runtime_osx_Module::classof(mod_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::runtime_Module>;
                    type To = cxx::UniquePtr<ffi::runtime_osx_Module>;
                    std::mem::transmute::<From, To>(ptr)
                };
                return Modules::Osx(osx::Module::from_ffi(raw));
            }
            panic!("Unsupported module")
        }
    }
}

impl Module for Modules {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::runtime_Module {
        match &self {
            Modules::Linux(module) => module.as_generic(),
            Modules::Windows(module) => module.as_generic(),
            Modules::Android(module) => module.as_generic(),
            Modules::Osx(module) => module.as_generic(),
        }
    }
}

/// Return an iterator over the different modules loaded in the current process.
pub fn modules() -> ModulesIt {
    ModulesIt::new(ffi::runtime_modules())
}

/// Find the module with the given name
pub fn module_from_name(name: &str) -> Option<Modules> {
    cxx::let_cxx_string!(s = name);
    into_optional(ffi::runtime_module_from_name(&s))
}

/// Find the module with the given name
pub fn module_from_path<P: AsRef<Path>>(path: P) -> Option<Modules> {
    cxx::let_cxx_string!(s = path.as_ref().to_str().unwrap());
    into_optional(ffi::runtime_module_from_path(&s))
}

/// Find the module that encompasses the given virtual address (absolute)
pub fn module_from_addr(addr: u64) -> Option<Modules> {
    into_optional(ffi::runtime_module_from_addr(addr))
}

/// Return the module that contains the code calling this function.
///
/// The bindings are statically linked, so it returns the executable or the
/// shared library (e.g. a `cdylib`) that embeds this crate.
pub fn current_module() -> Option<Modules> {
    into_optional(ffi::runtime_current_module())
}

declare_standalone_fwd_iterator!(
    ModulesIt,
    Modules,
    ffi::runtime_Module,
    ffi::runtime_it_modules
);
