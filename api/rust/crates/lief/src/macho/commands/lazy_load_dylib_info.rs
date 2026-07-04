use super::Command;
use crate::common::FromFFI;
use crate::{declare_iterator, to_slice};
use lief_ffi as ffi;
use std::marker::PhantomData;

/// Class representing the `LC_LAZY_LOAD_DYLIB_INFO` load command.
///
/// This command describes how to **lazily load a dylib**: instead of binding
/// the library and its symbols at launch time, `dyld` keeps the information
/// required to resolve the dylib on the first use of one of its symbols.
pub struct LazyLoadDylibInfo<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_LazyLoadDylibInfo>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl LazyLoadDylibInfo<'_> {
    /// Offset in the `__LINKEDIT` segment where the payload is located
    pub fn data_offset(&self) -> u32 {
        self.ptr.data_offset()
    }

    /// Size of the payload
    pub fn data_size(&self) -> u32 {
        self.ptr.data_size()
    }

    /// Raw payload as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }

    /// Load path of the dylib to bind lazily
    pub fn load_path(&self) -> String {
        self.ptr.load_path().to_string()
    }

    /// Image offset of the global flag that is set once the dylib has been loaded by dyld
    pub fn flag_image_offset(&self) -> u32 {
        self.ptr.flag_image_offset()
    }

    /// Raw flags associated with this command (see [`LazyLoadDylibInfo::may_be_missing`])
    pub fn flags(&self) -> u16 {
        self.ptr.flags()
    }

    /// Whether the dylib is allowed to be missing at runtime (weak linked)
    pub fn may_be_missing(&self) -> bool {
        self.ptr.may_be_missing()
    }

    /// Chained-fixups pointer format used by the binding chain
    pub fn pointer_format(&self) -> u16 {
        self.ptr.pointer_format()
    }

    /// Image offset of the fixup chain start used to bind the dylib's symbols
    pub fn chain_start_image_offset(&self) -> u32 {
        self.ptr.chain_start_image_offset()
    }

    /// List of the symbol names to bind lazily for this dylib
    pub fn symbols(&self) -> Vec<String> {
        let mut result = Vec::new();
        for entry in self.ptr.symbols().into_iter() {
            result.push(entry.to_string());
        }
        result
    }

    /// Iterator over the lazy-binding [`Fixup`] entries
    pub fn fixups(&self) -> Fixups<'_> {
        Fixups::new(self.ptr.fixups())
    }

    /// Change the load path of the dylib to bind lazily. The new path is
    /// serialized into the payload when the binary is rebuilt.
    pub fn set_load_path(&mut self, value: &str) {
        cxx::let_cxx_string!(value = value);
        self.ptr.pin_mut().set_load_path(&value);
    }

    /// Set the image offset of the global "loaded" flag.
    pub fn set_flag_image_offset(&mut self, value: u32) {
        self.ptr.pin_mut().set_flag_image_offset(value);
    }

    /// Set the raw flags associated with this command.
    pub fn set_flags(&mut self, value: u16) {
        self.ptr.pin_mut().set_flags(value);
    }

    /// Set or clear the "may be missing" (weak linked) flag bit.
    pub fn set_may_be_missing(&mut self, value: bool) {
        self.ptr.pin_mut().set_may_be_missing(value);
    }

    /// Set the chained-fixups pointer format used by the binding chain.
    pub fn set_pointer_format(&mut self, value: u16) {
        self.ptr.pin_mut().set_pointer_format(value);
    }

    /// Set the image offset of the fixup chain start.
    pub fn set_chain_start_image_offset(&mut self, value: u32) {
        self.ptr.pin_mut().set_chain_start_image_offset(value);
    }

    /// Append a symbol name to the list of symbols to bind lazily.
    pub fn add_symbol(&mut self, value: &str) {
        cxx::let_cxx_string!(value = value);
        self.ptr.pin_mut().add_symbol(&value);
    }

    /// Replace the list of symbol names to bind lazily. The new list is
    /// serialized into the payload when the binary is rebuilt.
    pub fn set_symbols(&mut self, symbols: &[&str]) {
        self.ptr.pin_mut().clear_symbols();
        for symbol in symbols {
            cxx::let_cxx_string!(symbol = *symbol);
            self.ptr.pin_mut().add_symbol(&symbol);
        }
    }
}

/// A single lazy-binding fixup decoded from a [`LazyLoadDylibInfo`] chain.
pub struct Fixup<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_LazyLoadDylibInfo_Fixup>,
    _owner: PhantomData<&'a ffi::MachO_LazyLoadDylibInfo>,
}

impl Fixup<'_> {
    /// Virtual address of the slot bound by this fixup
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }

    /// Index of the bound symbol in [`LazyLoadDylibInfo::symbols`]
    pub fn ordinal(&self) -> u32 {
        self.ptr.ordinal()
    }

    /// Name of the bound symbol (resolved from [`Fixup::ordinal`])
    pub fn symbol(&self) -> String {
        self.ptr.symbol().to_string()
    }

    /// Whether the bound pointer is authenticated (`arm64e` PAC)
    pub fn is_auth(&self) -> bool {
        self.ptr.is_auth()
    }
}

impl FromFFI<ffi::MachO_LazyLoadDylibInfo_Fixup> for Fixup<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_LazyLoadDylibInfo_Fixup>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for Fixup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fixup")
            .field("address", &self.address())
            .field("ordinal", &self.ordinal())
            .field("symbol", &self.symbol())
            .field("is_auth", &self.is_auth())
            .finish()
    }
}

impl std::fmt::Display for Fixup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

impl std::fmt::Debug for LazyLoadDylibInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("LazyLoadDylibInfo")
            .field("base", &base)
            .field("data_offset", &self.data_offset())
            .field("data_size", &self.data_size())
            .field("load_path", &self.load_path())
            .field("flags", &self.flags())
            .field("pointer_format", &self.pointer_format())
            .finish()
    }
}

impl FromFFI<ffi::MachO_LazyLoadDylibInfo> for LazyLoadDylibInfo<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_LazyLoadDylibInfo>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for LazyLoadDylibInfo<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(
    Fixups,
    Fixup<'a>,
    ffi::MachO_LazyLoadDylibInfo_Fixup,
    ffi::MachO_LazyLoadDylibInfo,
    ffi::MachO_LazyLoadDylibInfo_it_fixups
);
