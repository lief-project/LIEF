use super::Command;
use crate::common::FromFFI;
use crate::macho::export_info::ExportInfo;
use crate::to_slice;
use lief_ffi as ffi;
use std::marker::PhantomData;

use crate::declare_iterator;

/// Structure that represents the `LC_DYLD_EXPORTS_TRIE` command
///
/// In recent Mach-O binaries, this command replace the DyldInfo export trie buffer
pub struct DyldExportsTrie<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_DyldExportsTrie>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl DyldExportsTrie<'_> {
    /// Offset of the `LC_DYLD_EXPORTS_TRIE`. This offset should point in the
    /// `__LINKEDIT` segment
    pub fn data_offset(&self) -> u32 {
        self.ptr.data_offset()
    }

    /// Size of the `LC_DYLD_EXPORTS_TRIE` payload.
    pub fn data_size(&self) -> u32 {
        self.ptr.data_size()
    }

    /// Raw payload as a slice of bytes
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }

    /// Iterator over the [`crate::macho::ExportInfo`] associated with this command
    pub fn exports(&self) -> ExportInfos {
        ExportInfos::new(self.ptr.exports())
    }
}

impl std::fmt::Debug for DyldExportsTrie<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("DyldExportsTrie")
            .field("base", &base)
            .field("data_offset", &self.data_offset())
            .field("data_size", &self.data_size())
            .finish()
    }
}

impl FromFFI<ffi::MachO_DyldExportsTrie> for DyldExportsTrie<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_DyldExportsTrie>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for DyldExportsTrie<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(
    ExportInfos,
    ExportInfo<'a>,
    ffi::MachO_ExportInfo,
    ffi::MachO_DyldExportsTrie,
    ffi::MachO_DyldExportsTrie_it_exports
);
