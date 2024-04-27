use super::Command;
use crate::common::FromFFI;
use crate::macho::binding_info::Dyld;
use crate::macho::{BindingInfo, ExportInfo};
use std::marker::PhantomData;

use crate::{declare_iterator, declare_iterator_conv, to_slice};

use lief_ffi as ffi;

pub struct DyldInfo<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_DyldInfo>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl std::fmt::Debug for DyldInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("DyldInfo")
            .field("base", &base)
            .field("rebase_opcodes", &self.rebase_opcodes().is_empty())
            .field("bind_opcodes", &self.bind_opcodes().is_empty())
            .field("weak_bind_opcodes", &self.weak_bind_opcodes().is_empty())
            .field("lazy_bind_opcodes", &self.lazy_bind_opcodes().is_empty())
            .field("export_trie", &self.export_trie().is_empty())
            .finish()
    }
}

impl FromFFI<ffi::MachO_DyldInfo> for DyldInfo<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_DyldInfo>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl<'a> DyldInfo<'a> {
    pub fn rebase_opcodes(&self) -> &[u8] {
        to_slice!(self.ptr.rebase_opcodes());
    }
    pub fn bind_opcodes(&self) -> &[u8] {
        to_slice!(self.ptr.bind_opcodes());
    }
    pub fn weak_bind_opcodes(&self) -> &[u8] {
        to_slice!(self.ptr.weak_bind_opcodes());
    }
    pub fn lazy_bind_opcodes(&self) -> &[u8] {
        to_slice!(self.ptr.lazy_bind_opcodes());
    }
    pub fn export_trie(&self) -> &[u8] {
        to_slice!(self.ptr.export_trie());
    }
    pub fn bindings(&self) -> BindingInfos {
        BindingInfos::new(self.ptr.bindings())
    }
    pub fn exports(&self) -> ExportInfos {
        ExportInfos::new(self.ptr.exports())
    }
}

impl Command for DyldInfo<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator_conv!(
    BindingInfos,
    BindingInfo<'a>,
    ffi::MachO_BindingInfo,
    ffi::MachO_DyldInfo,
    ffi::MachO_DyldInfo_it_bindings,
    |n| BindingInfo::Dyld(Dyld::from_ffi(n))
);
declare_iterator!(
    ExportInfos,
    ExportInfo<'a>,
    ffi::MachO_ExportInfo,
    ffi::MachO_DyldInfo,
    ffi::MachO_DyldInfo_it_exports
);
