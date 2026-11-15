use std::marker::PhantomData;
use std::pin::Pin;

use crate::common::{AsFFI, FromFFI, into_optional};
use crate::generic;
use crate::{declare_iterator, enum_from_int};
use lief_ffi as ffi;

use super::commands::Dylib;
use super::{BindingInfo, ExportInfo};

/// Structure that represents a Symbol in a Mach-O file.
///
/// A Mach-O symbol can come from:
/// 1. The symbols command (LC_SYMTAB / SymbolCommand)
/// 2. The Dyld Export trie
/// 3. The Dyld Symbol bindings
pub struct Symbol<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Symbol>,
    _owner: PhantomData<&'a ()>,
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    Category: u32 {
        NONE = 0x00000000,
        LOCAL = 0x00000001,
        EXTERNAL = 0x00000002,
        UNDEFINED = 0x00000003,
        INDIRECT_ABS = 0x00000004,
        INDIRECT_LOCAL = 0x00000005,
        INDIRECT_ABS_LOCAL = 0x00000006,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    Origin: u32 {
        DYLD_EXPORT = 0x00000001,
        DYLD_BIND = 0x00000002,
        LC_SYMTAB = 0x00000003,
    }
}

enum_from_int! {
    /// Symbol type as defined by `nlist_xx.n_type & N_TYPE`
    #[allow(non_camel_case_types)]
    Type: u32 {
        /// The symbol is undefined
        UNDEFINED = 0x0,
        /// The symbol is absolute
        ABSOLUTE_SYM = 0x2,
        /// The symbol is defined in a specific section
        SECTION = 0xe,
        /// The symbol is undefined and the image is using a prebound value
        PREBOUND = 0xc,
        /// The symbol is defined to be the same as another symbol
        INDIRECT = 0xa,
    }
}

impl Symbol<'_> {
    pub fn get_type(&self) -> u8 {
        self.ptr.get_type()
    }

    /// It returns the number of sections in which this symbol can be found.
    /// If the symbol can't be found in any section, it returns 0 (`NO_SECT`)
    pub fn numberof_sections(&self) -> u8 {
        self.ptr.numberof_sections()
    }

    /// Return information about the symbol
    pub fn description(&self) -> u16 {
        self.ptr.description()
    }

    /// Return the origin of the symbol: from `LC_SYMTAB` from the Dyld information, ...
    pub fn origin(&self) -> Origin {
        Origin::from(self.ptr.origin())
    }

    /// Category of the symbol according to the `LC_DYSYMTAB` command
    pub fn category(&self) -> Category {
        Category::from(self.ptr.category())
    }

    /// Export info associated with this symbol (if any)
    pub fn export_info(&self) -> Option<ExportInfo<'_>> {
        into_optional(self.ptr.export_info())
    }

    /// Binding info associated with this symbol (if any)
    pub fn binding_info(&self) -> Option<BindingInfo<'_>> {
        into_optional(self.ptr.binding_info())
    }

    /// Return the library in which this symbol is defined (if any)
    pub fn library(&self) -> Option<Dylib<'_>> {
        into_optional(self.ptr.library())
    }

    /// Whether this symbol is external
    pub fn is_external(&self) -> bool {
        self.ptr.is_external()
    }

    /// Return the library ordinal for this symbol. A negative ordinal indicates
    /// a special value (e.g., -1 for `SELF_LIBRARY`, -2 for `MAIN_EXECUTABLE`)
    pub fn library_ordinal(&self) -> i32 {
        self.ptr.library_ordinal()
    }

    /// Try to demangle the symbol or return an empty string if it is not possible
    pub fn demangled_name(&self) -> String {
        self.ptr.demangled_name().to_string()
    }
}

impl std::fmt::Debug for Symbol<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("Symbol")
            .field("base", &base)
            .field("type", &self.get_type())
            .field("numberof_sections", &self.numberof_sections())
            .field("description", &self.description())
            .field("origin", &self.origin())
            .field("category", &self.category())
            .field("export_info", &self.export_info())
            .field("binding_info", &self.binding_info())
            .field("library", &self.library())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_Symbol> for Symbol<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_Symbol>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsFFI<ffi::MachO_Symbol> for Symbol<'_> {
    fn as_ffi(&self) -> &ffi::MachO_Symbol {
        self.ptr.as_ref().unwrap()
    }

    fn as_mut_ffi(&mut self) -> Pin<&mut ffi::MachO_Symbol> {
        self.ptr.pin_mut()
    }
}

impl generic::Symbol for Symbol<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_pin_mut_generic(&mut self) -> Pin<&mut ffi::AbstractSymbol> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::AbstractSymbol
                    as *mut ffi::AbstractSymbol)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

declare_iterator!(
    Symbols,
    Symbol<'a>,
    ffi::MachO_Symbol,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_symbols
);

declare_iterator!(
    ExportedSymbols,
    Symbol<'a>,
    ffi::MachO_Symbol,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_exported_symbols
);
