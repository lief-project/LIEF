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
use super::header::Header;
use super::relocation::Relocations;
use super::section::Sections;
use super::symbol::Symbols;
use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use crate::generic;
use crate::objc::Metadata;

/// This is the main interface to read and write Mach-O binary attributes.
///
/// Note that this structure implements the [`generic::Binary`] trait from which other generic
/// functions are exposed
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
    /// Return the main Mach-O header
    pub fn header(&self) -> Header {
        Header::from_ffi(self.ptr.header())
    }

    /// Return an iterator over the different [`crate::macho::Commands`] used by the
    /// Mach-O binary
    pub fn commands(&self) -> CommandsIter {
        CommandsIter::new(self.ptr.commands())
    }

    /// Return an iterator over the different [`crate::macho::Section`] of the binary
    pub fn sections(&self) -> Sections {
        Sections::new(self.ptr.sections())
    }

    /// Return an iterator over the different [`crate::macho::commands::Segment`] (`LC_SEGMENT/LC_SIGNATURE`)
    /// of the binary.
    pub fn segments(&self) -> Segments {
        Segments::new(self.ptr.segments())
    }

    /// Return an iterator over the [`crate::macho::commands::Dylib`] used by this binary
    pub fn libraries(&self) -> Libraries {
        Libraries::new(self.ptr.libraries())
    }

    /// Return an iterator over the different [`crate::macho::Relocation`] of this binary
    pub fn relocations(&self) -> Relocations {
        Relocations::new(self.ptr.relocations())
    }

    /// Return an iterator over the different [`crate::macho::Symbol`] of this binary
    pub fn symbols(&self) -> Symbols {
        Symbols::new(self.ptr.symbols())
    }

    /// Return the `LC_DYLD_INFO/LC_DYLD_INFO_ONLY` command if present
    pub fn dyld_info(&self) -> Option<DyldInfo> {
        into_optional(self.ptr.dyld_info())
    }

    /// Return the `LC_UUID` command if present
    pub fn uuid(&self) -> Option<UUID> {
        into_optional(self.ptr.uuid())
    }

    /// Return the `LC_MAIN` command if present
    pub fn main_command(&self) -> Option<Main> {
        into_optional(self.ptr.main_command())
    }

    /// Return the `LC_LOAD_DYLINKER/LC_ID_DYLINKER` command if present
    pub fn dylinker(&self) -> Option<Dylinker> {
        into_optional(self.ptr.dylinker())
    }

    /// Return the `LC_FUNCTION_STARTS` command if present
    pub fn function_starts(&self) -> Option<FunctionStarts> {
        into_optional(self.ptr.function_starts())
    }

    /// Return the `LC_SOURCE_VERSION` command if present
    pub fn source_version(&self) -> Option<SourceVersion> {
        into_optional(self.ptr.source_version())
    }

    /// Return the `LC_THREAD/LC_UNIXTHREAD` command if present
    pub fn thread_command(&self) -> Option<ThreadCommand> {
        into_optional(self.ptr.thread_command())
    }

    /// Return the `LC_RPATH` command if present
    pub fn rpath(&self) -> Option<RPath> {
        into_optional(self.ptr.rpath())
    }

    /// Return the `LC_SYMTAB` command if present
    pub fn symbol_command(&self) -> Option<SymbolCommand> {
        into_optional(self.ptr.symbol_command())
    }

    /// Return the `LC_DYSYMTAB` command if present
    pub fn dynamic_symbol(&self) -> Option<DynamicSymbolCommand> {
        into_optional(self.ptr.dynamic_symbol_command())
    }

    /// Return the `LC_CODE_SIGNATURE` command if present
    pub fn code_signature(&self) -> Option<CodeSignature> {
        into_optional(self.ptr.code_signature())
    }

    /// Return the `LC_DYLIB_CODE_SIGN_DRS` command if present
    pub fn code_signature_dir(&self) -> Option<CodeSignatureDir> {
        into_optional(self.ptr.code_signature_dir())
    }

    /// Return the `LC_DATA_IN_CODE` command if present
    pub fn data_in_code(&self) -> Option<DataInCode> {
        into_optional(self.ptr.data_in_code())
    }

    /// Return the `LC_SEGMENT_SPLIT_INFO` command if present
    pub fn segment_split_info(&self) -> Option<SegmentSplitInfo> {
        into_optional(self.ptr.segment_split_info())
    }

    /// Return the `LC_ENCRYPTION_INFO/LC_ENCRYPTION_INFO_64` command if present
    pub fn encryption_info(&self) -> Option<EncryptionInfo> {
        into_optional(self.ptr.encryption_info())
    }

    /// Return the `LC_SUB_FRAMEWORK` command if present
    pub fn sub_framework(&self) -> Option<SubFramework> {
        into_optional(self.ptr.sub_framework())
    }

    /// Return the `LC_DYLD_ENVIRONMENT` command if present
    pub fn dyld_environment(&self) -> Option<DyldEnvironment> {
        into_optional(self.ptr.dyld_environment())
    }

    /// Return the `LC_BUILD_VERSION` command if present
    pub fn build_version(&self) -> Option<BuildVersion> {
        into_optional(self.ptr.build_version())
    }

    /// Return the `LC_DYLD_CHAINED_FIXUPS` command if present
    pub fn dyld_chained_fixups(&self) -> Option<DyldChainedFixups> {
        into_optional(self.ptr.dyld_chained_fixups())
    }

    /// Return the `LC_DYLD_EXPORTS_TRIE` command if present
    pub fn dyld_exports_trie(&self) -> Option<DyldExportsTrie> {
        into_optional(self.ptr.dyld_exports_trie())
    }

    /// Return the `LC_TWOLEVEL_HINTS` command if present
    pub fn two_level_hints(&self) -> Option<TwoLevelHints> {
        into_optional(self.ptr.two_level_hints())
    }

    /// Return the `LC_LINKER_OPTIMIZATION_HINT` command if present
    pub fn linker_opt_hint(&self) -> Option<LinkerOptHint> {
        into_optional(self.ptr.linker_opt_hint())
    }

    /// Return the `LC_VERSION_MIN_MACOSX/VERSION_MIN_IPHONEOS` command if present
    pub fn version_min(&self) -> Option<VersionMin> {
        into_optional(self.ptr.version_min())
    }

    /// Check if the binary is supporting ARM64 pointer authentication (arm64e)
    pub fn support_arm64_ptr_auth(&self) -> bool {
        self.ptr.support_arm64_ptr_auth()
    }

    /// Return Objective-C metadata if present
    pub fn objc_metadata(&self) -> Option<Metadata> {
        into_optional(self.ptr.objc_metadata())
    }
}

impl generic::Binary for Binary {
    fn as_generic(&self) -> &ffi::AbstractBinary {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
