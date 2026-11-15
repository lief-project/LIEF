use lief_ffi as ffi;
use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;

use super::SymbolVersion;
use crate::common::{FromFFI, into_optional};
use crate::elf::Section;
use crate::generic;
use crate::{declare_iterator, enum_from_int};

/// Structure which represents an ELF symbol
pub struct Symbol<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_Symbol>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    #[derive(PartialOrd, Ord)]
    Binding: u32 {
        /// Local symbol
        LOCAL = 0x00000000,
        /// Global symbol
        GLOBAL = 0x00000001,
        /// Weak symbol
        WEAK = 0x00000002,
        /// Unique symbol
        GNU_UNIQUE = 0x0000000a,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    #[derive(PartialOrd, Ord)]
    /// Type of the symbol. This enum matches the `STT_xxx` values of the ELF
    /// specs
    Type: u32 {
        /// Symbol's type is not specified
        NOTYPE = 0x00000000,
        /// Symbol is a data object (variable, array, etc.)
        OBJECT = 0x00000001,
        /// Symbol is executable code (function, etc.)
        FUNC = 0x00000002,
        /// Symbol refers to a section
        SECTION = 0x00000003,
        /// Local, absolute symbol that refers to a file
        FILE = 0x00000004,
        /// An uninitialized common block
        COMMON = 0x00000005,
        /// Thread local data object
        TLS = 0x00000006,
        /// GNU indirect function
        GNU_IFUNC = 0x0000000a,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    #[derive(PartialOrd, Ord)]
    /// Visibility of the symbol. This enum matches the `STV_xxx` values of the
    /// official ELF specs
    Visibility: u32 {
        /// Visibility is specified by binding type
        DEFAULT = 0x00000000,
        /// Defined by processor supplements
        INTERNAL = 0x00000001,
        /// Not visible to other components
        HIDDEN = 0x00000002,
        /// Visible in other components but not preemptable
        PROTECTED = 0x00000003,
    }
}

impl Symbol<'_> {
    /// The symbol's type provides a general classification for the associated entity
    pub fn get_type(&self) -> Type {
        Type::from(self.ptr.get_type())
    }

    /// The symbol's binding determines the linkage visibility and behavior
    pub fn binding(&self) -> Binding {
        Binding::from(self.ptr.binding())
    }

    /// This member specifies the symbol's type and binding attributes.
    pub fn information(&self) -> u8 {
        self.ptr.information()
    }

    /// Alias for [`Symbol::visibility`]
    pub fn other(&self) -> u8 {
        self.ptr.other()
    }

    /// ELF Section index associated with the symbol
    pub fn section_idx(&self) -> u16 {
        self.ptr.section_idx()
    }

    /// Symbol visibility
    pub fn visibility(&self) -> Visibility {
        Visibility::from(self.ptr.visibility())
    }

    /// Section associated with the symbol (if any)
    pub fn section(&self) -> Option<Section<'_>> {
        into_optional(self.ptr.section())
    }

    /// Return the SymbolVersion associated with this symbol (if any)
    pub fn symbol_version(&self) -> Option<SymbolVersion<'_>> {
        into_optional(self.ptr.symbol_version())
    }

    /// Try to demangle the symbol or return an empty string if it is not possible
    pub fn demangled_name(&self) -> String {
        self.ptr.demangled_name().to_string()
    }

    /// True if the symbol is a GNU indirect function defined by the binary
    pub fn is_local_ifunc(&self) -> bool {
        self.ptr.is_local_ifunc()
    }

    /// True if references to the symbol cannot be preempted by another module:
    /// it has local binding or hidden, internal, or protected visibility.
    pub fn binds_locally(&self) -> bool {
        self.ptr.binds_locally()
    }
}

impl fmt::Debug for Symbol<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("Symbol")
            .field("base", &base)
            .field("type", &self.get_type())
            .field("binding", &self.binding())
            .field("information", &self.information())
            .field("other", &self.other())
            .field("section_idx", &self.section_idx())
            .field("visibility", &self.visibility())
            .field("section", &self.section())
            .field("symbol_version", &self.symbol_version())
            .finish()
    }
}

impl FromFFI<ffi::ELF_Symbol> for Symbol<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_Symbol>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl crate::common::AsFFI<ffi::ELF_Symbol> for Symbol<'_> {
    fn as_ffi(&self) -> &ffi::ELF_Symbol {
        self.ptr.as_ref().unwrap()
    }

    fn as_mut_ffi(&mut self) -> Pin<&mut ffi::ELF_Symbol> {
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

impl fmt::Display for Symbol<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

declare_iterator!(
    DynamicSymbols,
    Symbol<'a>,
    ffi::ELF_Symbol,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_dynamic_symbols
);
declare_iterator!(
    ExportedSymbols,
    Symbol<'a>,
    ffi::ELF_Symbol,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_exported_symbols
);
declare_iterator!(
    ImportedSymbols,
    Symbol<'a>,
    ffi::ELF_Symbol,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_imported_symbols
);
declare_iterator!(
    SymtabSymbols,
    Symbol<'a>,
    ffi::ELF_Symbol,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_symtab_symbols
);
