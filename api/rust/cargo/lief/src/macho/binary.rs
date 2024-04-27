use super::commands::build_version::BuildVersion;
use super::commands::code_signature::CodeSignature;
use super::commands::code_signature_dir::CodeSignatureDir;
use super::commands::data_in_code::DataInCode;
use super::commands::dyld_chained_fixups::DyldChainedFixups;
use super::commands::dyld_environment::DyldEnvironment;
use super::commands::dyld_export_trie::DyldExportsTrie;
use super::commands::dyldinfo::DyldInfo;
use super::commands::dylib::Libraries;
use super::commands::dylinker::Dylinker;
use super::commands::dynamic_symbol_command::DynamicSymbolCommand;
use super::commands::encryption_info::EncryptionInfo;
use super::commands::functionstarts::FunctionStarts;
use super::commands::linker_opt_hint::LinkerOptHint;
use super::commands::main_cmd::Main;
use super::commands::rpath::RPath;
use super::commands::segment::Segments;
use super::commands::segment_split_info::SegmentSplitInfo;
use super::commands::source_version::SourceVersion;
use super::commands::sub_framework::SubFramework;
use super::commands::symbol_command::SymbolCommand;
use super::commands::thread_command::ThreadCommand;
use super::commands::two_level_hints::TwoLevelHints;
use super::commands::uuid::UUID;
use super::commands::version_min::VersionMin;
use super::commands::CommandsIter;
use super::relocation::Relocations;
use super::section::Sections;
use super::symbol::Symbols;
use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use crate::generic;

pub struct Binary {
    ptr: cxx::UniquePtr<ffi::MachO_Binary>,
}

impl std::fmt::Debug for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binary").finish()
    }
}

impl FromFFI<ffi::MachO_Binary> for Binary {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_Binary>) -> Self {
        Binary { ptr }
    }
}

impl Binary {
    pub fn commands(&self) -> CommandsIter {
        CommandsIter::new(self.ptr.commands())
    }

    pub fn sections(&self) -> Sections {
        Sections::new(self.ptr.sections())
    }

    pub fn segments(&self) -> Segments {
        Segments::new(self.ptr.segments())
    }

    pub fn libraries(&self) -> Libraries {
        Libraries::new(self.ptr.libraries())
    }

    pub fn relocations(&self) -> Relocations {
        Relocations::new(self.ptr.relocations())
    }

    pub fn symbols(&self) -> Symbols {
        Symbols::new(self.ptr.symbols())
    }

    pub fn dyld_info(&self) -> Option<DyldInfo> {
        into_optional(self.ptr.dyld_info())
    }

    pub fn uuid(&self) -> Option<UUID> {
        into_optional(self.ptr.uuid())
    }

    pub fn main_command(&self) -> Option<Main> {
        into_optional(self.ptr.main_command())
    }

    pub fn dylinker(&self) -> Option<Dylinker> {
        into_optional(self.ptr.dylinker())
    }

    pub fn function_starts(&self) -> Option<FunctionStarts> {
        into_optional(self.ptr.function_starts())
    }

    pub fn source_version(&self) -> Option<SourceVersion> {
        into_optional(self.ptr.source_version())
    }

    pub fn thread_command(&self) -> Option<ThreadCommand> {
        into_optional(self.ptr.thread_command())
    }

    pub fn rpath(&self) -> Option<RPath> {
        into_optional(self.ptr.rpath())
    }

    pub fn symbol_command(&self) -> Option<SymbolCommand> {
        into_optional(self.ptr.symbol_command())
    }

    pub fn dynamic_symbol(&self) -> Option<DynamicSymbolCommand> {
        into_optional(self.ptr.dynamic_symbol_command())
    }

    pub fn code_signature(&self) -> Option<CodeSignature> {
        into_optional(self.ptr.code_signature())
    }

    pub fn code_signature_dir(&self) -> Option<CodeSignatureDir> {
        into_optional(self.ptr.code_signature_dir())
    }

    pub fn data_in_code(&self) -> Option<DataInCode> {
        into_optional(self.ptr.data_in_code())
    }

    pub fn segment_split_info(&self) -> Option<SegmentSplitInfo> {
        into_optional(self.ptr.segment_split_info())
    }

    pub fn encryption_info(&self) -> Option<EncryptionInfo> {
        into_optional(self.ptr.encryption_info())
    }

    pub fn sub_framework(&self) -> Option<SubFramework> {
        into_optional(self.ptr.sub_framework())
    }

    pub fn dyld_environment(&self) -> Option<DyldEnvironment> {
        into_optional(self.ptr.dyld_environment())
    }

    pub fn build_version(&self) -> Option<BuildVersion> {
        into_optional(self.ptr.build_version())
    }

    pub fn dyld_chained_fixups(&self) -> Option<DyldChainedFixups> {
        into_optional(self.ptr.dyld_chained_fixups())
    }

    pub fn dyld_exports_trie(&self) -> Option<DyldExportsTrie> {
        into_optional(self.ptr.dyld_exports_trie())
    }

    pub fn two_level_hints(&self) -> Option<TwoLevelHints> {
        into_optional(self.ptr.two_level_hints())
    }

    pub fn linker_opt_hint(&self) -> Option<LinkerOptHint> {
        into_optional(self.ptr.linker_opt_hint())
    }

    pub fn version_min(&self) -> Option<VersionMin> {
        into_optional(self.ptr.version_min())
    }
}

impl generic::Binary for Binary {
    fn as_generic(&self) -> &ffi::AbstractBinary {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
