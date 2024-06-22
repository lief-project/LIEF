use std::marker::PhantomData;

use lief_ffi as ffi;
pub mod build_version;
pub mod code_signature;
pub mod code_signature_dir;
pub mod data_in_code;
pub mod dyld_chained_fixups;
pub mod dyld_environment;
pub mod dyld_export_trie;
pub mod dyldinfo;
pub mod dylib;
pub mod dylinker;
pub mod dynamic_symbol_command;
pub mod encryption_info;
pub mod functionstarts;
pub mod linker_opt_hint;
pub mod main_cmd;
pub mod rpath;
pub mod segment;
pub mod segment_split_info;
pub mod source_version;
pub mod sub_framework;
pub mod symbol_command;
pub mod thread_command;
pub mod two_level_hints;
pub mod uuid;
pub mod version_min;
pub mod unknown;

#[doc(inline)]
pub use build_version::BuildVersion;
#[doc(inline)]
pub use code_signature::CodeSignature;
#[doc(inline)]
pub use code_signature_dir::CodeSignatureDir;
#[doc(inline)]
pub use data_in_code::DataInCode;
#[doc(inline)]
pub use dyld_chained_fixups::DyldChainedFixups;
#[doc(inline)]
pub use dyld_environment::DyldEnvironment;
#[doc(inline)]
pub use dyld_export_trie::DyldExportsTrie;
#[doc(inline)]
pub use dyldinfo::DyldInfo;
#[doc(inline)]
pub use dylib::{Dylib, Libraries};
#[doc(inline)]
pub use dylinker::Dylinker;
#[doc(inline)]
pub use dynamic_symbol_command::DynamicSymbolCommand;
#[doc(inline)]
pub use encryption_info::EncryptionInfo;
#[doc(inline)]
pub use functionstarts::FunctionStarts;
#[doc(inline)]
pub use linker_opt_hint::LinkerOptHint;
#[doc(inline)]
pub use main_cmd::Main;
#[doc(inline)]
pub use rpath::RPath;
#[doc(inline)]
pub use segment::Segment;
#[doc(inline)]
pub use segment_split_info::SegmentSplitInfo;
#[doc(inline)]
pub use source_version::SourceVersion;
#[doc(inline)]
pub use sub_framework::SubFramework;
#[doc(inline)]
pub use symbol_command::SymbolCommand;
#[doc(inline)]
pub use thread_command::ThreadCommand;
#[doc(inline)]
pub use two_level_hints::TwoLevelHints;
#[doc(inline)]
pub use uuid::UUID;
#[doc(inline)]
pub use version_min::VersionMin;
#[doc(inline)]
pub use unknown::Unknown;

use crate::common::FromFFI;
use crate::{declare_iterator, to_slice};

#[derive(Debug, Copy, Clone)]
pub enum LoadCommandTypes {
    BuildVersion,
    CodeSignature,
    DataInCode,
    DyldChainedFixups,
    DyldEnvironment,
    DyldExportsTrie,
    DyldInfo,
    DyldInfoOnly,
    DylibCodeSignDrs,
    Dysymtab,
    EncryptionInfo,
    EncryptionInfo64,
    FilesetEntry,
    FunctionStarts,
    Fvmfile,
    Ident,
    Idfvmlib,
    IdDylib,
    IdDylinker,
    LazyLoadDylib,
    LinkerOptimizationHint,
    LinkerOption,
    LoadFvmLib,
    LoadDylib,
    LoadDylinker,
    LoadUpwardDylib,
    LoadWeakDylib,
    Main,
    Note,
    PrebindCksum,
    PreboundDylib,
    Prepage,
    ReExportDylib,
    Routines,
    Routines64,
    Rpath,
    Segment,
    Segment64,
    SegmentSplitInfo,
    SourceVersion,
    SubClient,
    SubFramework,
    SubLibrary,
    SubUmbrella,
    Symseg,
    Symtab,
    Thread,
    TwoLevelHints,
    Unixthread,
    Uuid,
    VersionMinIphoneOS,
    VersionMinMacOSX,
    VersionMinTvOS,
    VersionMinWatchOS,

    LiefUnknown,
    Unknown(u64),
}
impl LoadCommandTypes {
    const LC_BUILD_VERSION: u64 = 0x00000032;
    const LC_CODE_SIGNATURE: u64 = 0x0000001D;
    const LC_DATA_IN_CODE: u64 = 0x00000029;
    const LC_DYLD_CHAINED_FIXUPS: u64 = 0x80000034;
    const LC_DYLD_ENVIRONMENT: u64 = 0x00000027;
    const LC_DYLD_EXPORTS_TRIE: u64 = 0x80000033;
    const LC_DYLD_INFO: u64 = 0x00000022;
    const LC_DYLD_INFO_ONLY: u64 = 0x80000022;
    const LC_DYLIB_CODE_SIGN_DRS: u64 = 0x0000002B;
    const LC_DYSYMTAB: u64 = 0x0000000B;
    const LC_ENCRYPTION_INFO: u64 = 0x00000021;
    const LC_ENCRYPTION_INFO_64: u64 = 0x0000002C;
    const LC_FILESET_ENTRY: u64 = 0x80000035;
    const LC_FUNCTION_STARTS: u64 = 0x00000026;
    const LC_FVMFILE: u64 = 0x00000009;
    const LC_IDENT: u64 = 0x00000008;
    const LC_IDFVMLIB: u64 = 0x00000007;
    const LC_ID_DYLIB: u64 = 0x0000000D;
    const LC_ID_DYLINKER: u64 = 0x0000000F;
    const LC_LAZY_LOAD_DYLIB: u64 = 0x00000020;
    const LC_LINKER_OPTIMIZATION_HINT: u64 = 0x0000002E;
    const LC_LINKER_OPTION: u64 = 0x0000002D;
    const LC_LOADFVMLIB: u64 = 0x00000006;
    const LC_LOAD_DYLIB: u64 = 0x0000000C;
    const LC_LOAD_DYLINKER: u64 = 0x0000000E;
    const LC_LOAD_UPWARD_DYLIB: u64 = 0x80000023;
    const LC_LOAD_WEAK_DYLIB: u64 = 0x80000018;
    const LC_MAIN: u64 = 0x80000028;
    const LC_NOTE: u64 = 0x00000031;
    const LC_PREBIND_CKSUM: u64 = 0x00000017;
    const LC_PREBOUND_DYLIB: u64 = 0x00000010;
    const LC_PREPAGE: u64 = 0x0000000A;
    const LC_REEXPORT_DYLIB: u64 = 0x8000001F;
    const LC_ROUTINES: u64 = 0x00000011;
    const LC_ROUTINES_64: u64 = 0x0000001A;
    const LC_RPATH: u64 = 0x8000001C;
    const LC_SEGMENT: u64 = 0x00000001;
    const LC_SEGMENT_64: u64 = 0x00000019;
    const LC_SEGMENT_SPLIT_INFO: u64 = 0x0000001E;
    const LC_SOURCE_VERSION: u64 = 0x0000002A;
    const LC_SUB_CLIENT: u64 = 0x00000014;
    const LC_SUB_FRAMEWORK: u64 = 0x00000012;
    const LC_SUB_LIBRARY: u64 = 0x00000015;
    const LC_SUB_UMBRELLA: u64 = 0x00000013;
    const LC_SYMSEG: u64 = 0x00000003;
    const LC_SYMTAB: u64 = 0x00000002;
    const LC_THREAD: u64 = 0x00000004;
    const LC_TWOLEVEL_HINTS: u64 = 0x00000016;
    const LC_UNIXTHREAD: u64 = 0x00000005;
    const LC_UUID: u64 = 0x0000001B;
    const LC_VERSION_MIN_IPHONEOS: u64 = 0x00000025;
    const LC_VERSION_MIN_MACOSX: u64 = 0x00000024;
    const LC_VERSION_MIN_TVOS: u64 = 0x0000002F;
    const LC_VERSION_MIN_WATCHOS: u64 = 0x00000030;

    const LIEF_UNKNOWN: u64 = 0xffee0001;

    pub fn from_value(value: u64) -> Self {
        match value {
            LoadCommandTypes::LC_BUILD_VERSION => LoadCommandTypes::BuildVersion,
            LoadCommandTypes::LC_CODE_SIGNATURE => LoadCommandTypes::CodeSignature,
            LoadCommandTypes::LC_DATA_IN_CODE => LoadCommandTypes::DataInCode,
            LoadCommandTypes::LC_DYLD_CHAINED_FIXUPS => LoadCommandTypes::DyldChainedFixups,
            LoadCommandTypes::LC_DYLD_ENVIRONMENT => LoadCommandTypes::DyldEnvironment,
            LoadCommandTypes::LC_DYLD_EXPORTS_TRIE => LoadCommandTypes::DyldExportsTrie,
            LoadCommandTypes::LC_DYLD_INFO => LoadCommandTypes::DyldInfo,
            LoadCommandTypes::LC_DYLD_INFO_ONLY => LoadCommandTypes::DyldInfoOnly,
            LoadCommandTypes::LC_DYLIB_CODE_SIGN_DRS => LoadCommandTypes::DylibCodeSignDrs,
            LoadCommandTypes::LC_DYSYMTAB => LoadCommandTypes::Dysymtab,
            LoadCommandTypes::LC_ENCRYPTION_INFO => LoadCommandTypes::EncryptionInfo,
            LoadCommandTypes::LC_ENCRYPTION_INFO_64 => LoadCommandTypes::EncryptionInfo64,
            LoadCommandTypes::LC_FILESET_ENTRY => LoadCommandTypes::FilesetEntry,
            LoadCommandTypes::LC_FUNCTION_STARTS => LoadCommandTypes::FunctionStarts,
            LoadCommandTypes::LC_FVMFILE => LoadCommandTypes::Fvmfile,
            LoadCommandTypes::LC_IDENT => LoadCommandTypes::Ident,
            LoadCommandTypes::LC_IDFVMLIB => LoadCommandTypes::Idfvmlib,
            LoadCommandTypes::LC_ID_DYLIB => LoadCommandTypes::IdDylib,
            LoadCommandTypes::LC_ID_DYLINKER => LoadCommandTypes::IdDylinker,
            LoadCommandTypes::LC_LAZY_LOAD_DYLIB => LoadCommandTypes::LazyLoadDylib,
            LoadCommandTypes::LC_LINKER_OPTIMIZATION_HINT => {
                LoadCommandTypes::LinkerOptimizationHint
            }
            LoadCommandTypes::LC_LINKER_OPTION => LoadCommandTypes::LinkerOption,
            LoadCommandTypes::LC_LOADFVMLIB => LoadCommandTypes::LoadFvmLib,
            LoadCommandTypes::LC_LOAD_DYLIB => LoadCommandTypes::LoadDylib,
            LoadCommandTypes::LC_LOAD_DYLINKER => LoadCommandTypes::LoadDylinker,
            LoadCommandTypes::LC_LOAD_UPWARD_DYLIB => LoadCommandTypes::LoadUpwardDylib,
            LoadCommandTypes::LC_LOAD_WEAK_DYLIB => LoadCommandTypes::LoadWeakDylib,
            LoadCommandTypes::LC_MAIN => LoadCommandTypes::Main,
            LoadCommandTypes::LC_NOTE => LoadCommandTypes::Note,
            LoadCommandTypes::LC_PREBIND_CKSUM => LoadCommandTypes::PrebindCksum,
            LoadCommandTypes::LC_PREBOUND_DYLIB => LoadCommandTypes::PreboundDylib,
            LoadCommandTypes::LC_PREPAGE => LoadCommandTypes::Prepage,
            LoadCommandTypes::LC_REEXPORT_DYLIB => LoadCommandTypes::ReExportDylib,
            LoadCommandTypes::LC_ROUTINES => LoadCommandTypes::Routines,
            LoadCommandTypes::LC_ROUTINES_64 => LoadCommandTypes::Routines64,
            LoadCommandTypes::LC_RPATH => LoadCommandTypes::Rpath,
            LoadCommandTypes::LC_SEGMENT => LoadCommandTypes::Segment,
            LoadCommandTypes::LC_SEGMENT_64 => LoadCommandTypes::Segment64,
            LoadCommandTypes::LC_SEGMENT_SPLIT_INFO => LoadCommandTypes::SegmentSplitInfo,
            LoadCommandTypes::LC_SOURCE_VERSION => LoadCommandTypes::SourceVersion,
            LoadCommandTypes::LC_SUB_CLIENT => LoadCommandTypes::SubClient,
            LoadCommandTypes::LC_SUB_FRAMEWORK => LoadCommandTypes::SubFramework,
            LoadCommandTypes::LC_SUB_LIBRARY => LoadCommandTypes::SubLibrary,
            LoadCommandTypes::LC_SUB_UMBRELLA => LoadCommandTypes::SubUmbrella,
            LoadCommandTypes::LC_SYMSEG => LoadCommandTypes::Symseg,
            LoadCommandTypes::LC_SYMTAB => LoadCommandTypes::Symtab,
            LoadCommandTypes::LC_THREAD => LoadCommandTypes::Thread,
            LoadCommandTypes::LC_TWOLEVEL_HINTS => LoadCommandTypes::TwoLevelHints,
            LoadCommandTypes::LC_UNIXTHREAD => LoadCommandTypes::Unixthread,
            LoadCommandTypes::LC_UUID => LoadCommandTypes::Uuid,
            LoadCommandTypes::LC_VERSION_MIN_IPHONEOS => LoadCommandTypes::VersionMinIphoneOS,
            LoadCommandTypes::LC_VERSION_MIN_MACOSX => LoadCommandTypes::VersionMinMacOSX,
            LoadCommandTypes::LC_VERSION_MIN_TVOS => LoadCommandTypes::VersionMinTvOS,
            LoadCommandTypes::LC_VERSION_MIN_WATCHOS => LoadCommandTypes::VersionMinWatchOS,
            LoadCommandTypes::LIEF_UNKNOWN => LoadCommandTypes::LiefUnknown,
            _ => LoadCommandTypes::Unknown(value),
        }
    }
}

#[derive(Debug)]
/// Enum that wraps all the different Mach-O load commands (`LC_xxx`).
/// Note that all these commands implements the trait: [`Command`]
pub enum Commands<'a> {
    Generic(Generic<'a>),
    BuildVersion(BuildVersion<'a>),
    CodeSignature(CodeSignature<'a>),
    CodeSignatureDir(CodeSignatureDir<'a>),
    DataInCode(DataInCode<'a>),
    DyldChainedFixups(DyldChainedFixups<'a>),
    DyldEnvironment(DyldEnvironment<'a>),
    DyldExportsTrie(DyldExportsTrie<'a>),
    DyldInfo(DyldInfo<'a>),
    Dylib(Dylib<'a>),
    Dylinker(Dylinker<'a>),
    DynamicSymbolCommand(DynamicSymbolCommand<'a>),
    EncryptionInfo(EncryptionInfo<'a>),
    FunctionStarts(FunctionStarts<'a>),
    LinkerOptHint(LinkerOptHint<'a>),
    Main(Main<'a>),
    RPath(RPath<'a>),
    Segment(Segment<'a>),
    SegmentSplitInfo(SegmentSplitInfo<'a>),
    SourceVersion(SourceVersion<'a>),
    SubFramework(SubFramework<'a>),
    SymbolCommand(SymbolCommand<'a>),
    ThreadCommand(ThreadCommand<'a>),
    TwoLevelHints(TwoLevelHints<'a>),
    UUID(UUID<'a>),
    VersionMin(VersionMin<'a>),
    Unknown(Unknown<'a>),
}

impl<'a> Commands<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::MachO_Command>) -> Self {
        unsafe {
            let cmd_ref = ffi_entry.as_ref().unwrap();

            if ffi::MachO_Dylib::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_Dylib>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::Dylib(Dylib::from_ffi(raw))
            } else if ffi::MachO_Main::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_Main>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::Main(Main::from_ffi(raw))
            } else if ffi::MachO_SegmentCommand::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_SegmentCommand>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::Segment(Segment::from_ffi(raw))
            } else if ffi::MachO_DyldInfo::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_DyldInfo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::DyldInfo(DyldInfo::from_ffi(raw))
            } else if ffi::MachO_UUIDCommand::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_UUIDCommand>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::UUID(UUID::from_ffi(raw))
            } else if ffi::MachO_Dylinker::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_Dylinker>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::Dylinker(Dylinker::from_ffi(raw))
            } else if ffi::MachO_FunctionStarts::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_FunctionStarts>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::FunctionStarts(FunctionStarts::from_ffi(raw))
            } else if ffi::MachO_SourceVersion::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_SourceVersion>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::SourceVersion(SourceVersion::from_ffi(raw))
            } else if ffi::MachO_ThreadCommand::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_ThreadCommand>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::ThreadCommand(ThreadCommand::from_ffi(raw))
            } else if ffi::MachO_RPathCommand::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_RPathCommand>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::RPath(RPath::from_ffi(raw))
            } else if ffi::MachO_SymbolCommand::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_SymbolCommand>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::SymbolCommand(SymbolCommand::from_ffi(raw))
            } else if ffi::MachO_DynamicSymbolCommand::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_DynamicSymbolCommand>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::DynamicSymbolCommand(DynamicSymbolCommand::from_ffi(raw))
            } else if ffi::MachO_CodeSignature::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_CodeSignature>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::CodeSignature(CodeSignature::from_ffi(raw))
            } else if ffi::MachO_CodeSignatureDir::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_CodeSignatureDir>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::CodeSignatureDir(CodeSignatureDir::from_ffi(raw))
            } else if ffi::MachO_DataInCode::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_DataInCode>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::DataInCode(DataInCode::from_ffi(raw))
            } else if ffi::MachO_SegmentSplitInfo::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_SegmentSplitInfo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::SegmentSplitInfo(SegmentSplitInfo::from_ffi(raw))
            } else if ffi::MachO_EncryptionInfo::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_EncryptionInfo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::EncryptionInfo(EncryptionInfo::from_ffi(raw))
            } else if ffi::MachO_SubFramework::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_SubFramework>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::SubFramework(SubFramework::from_ffi(raw))
            } else if ffi::MachO_DyldEnvironment::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_DyldEnvironment>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::DyldEnvironment(DyldEnvironment::from_ffi(raw))
            } else if ffi::MachO_BuildVersion::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_BuildVersion>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::BuildVersion(BuildVersion::from_ffi(raw))
            } else if ffi::MachO_DyldChainedFixups::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_DyldChainedFixups>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::DyldChainedFixups(DyldChainedFixups::from_ffi(raw))
            } else if ffi::MachO_DyldExportsTrie::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_DyldExportsTrie>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::DyldExportsTrie(DyldExportsTrie::from_ffi(raw))
            } else if ffi::MachO_TwoLevelHints::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_TwoLevelHints>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::TwoLevelHints(TwoLevelHints::from_ffi(raw))
            } else if ffi::MachO_LinkerOptHint::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_LinkerOptHint>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::LinkerOptHint(LinkerOptHint::from_ffi(raw))
            } else if ffi::MachO_VersionMin::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_VersionMin>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::VersionMin(VersionMin::from_ffi(raw))
            } else if ffi::MachO_UnknownCommand::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_UnknownCommand>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::Unknown(Unknown::from_ffi(raw))
            } else {
                Commands::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}

pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_Command>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl std::fmt::Debug for Generic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generic").finish()
    }
}

impl FromFFI<ffi::MachO_Command> for Generic<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_Command>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

/// Trait shared by **all** the load command: [`Commands`]
pub trait Command {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::MachO_Command;

    /// Size of the command (should be greather than ``sizeof(load_command)``)
    fn size(&self) -> u32 {
        self.get_base().size()
    }

    /// Offset of the command within the *Load Command Table*
    fn offset(&self) -> u64 {
        self.get_base().command_offset()
    }

    /// The command's type
    fn command_type(&self) -> LoadCommandTypes {
        LoadCommandTypes::from_value(self.get_base().cmd_type())
    }

    /// The raw command as a slice of bytes
    fn data(&self) -> &[u8] {
        to_slice!(self.get_base().data());
    }
}

impl Command for Commands<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        match &self {
            Commands::Generic(cmd) => {
                cmd.get_base()
            }
            Commands::BuildVersion(cmd) => {
                cmd.get_base()
            }
            Commands::CodeSignature(cmd) => {
                cmd.get_base()
            }
            Commands::CodeSignatureDir(cmd) => {
                cmd.get_base()
            }
            Commands::DataInCode(cmd) => {
                cmd.get_base()
            }
            Commands::DyldChainedFixups(cmd) => {
                cmd.get_base()
            }
            Commands::DyldEnvironment(cmd) => {
                cmd.get_base()
            }
            Commands::DyldExportsTrie(cmd) => {
                cmd.get_base()
            }
            Commands::DyldInfo(cmd) => {
                cmd.get_base()
            }
            Commands::Dylib(cmd) => {
                cmd.get_base()
            }
            Commands::Dylinker(cmd) => {
                cmd.get_base()
            }
            Commands::DynamicSymbolCommand(cmd) => {
                cmd.get_base()
            }
            Commands::EncryptionInfo(cmd) => {
                cmd.get_base()
            }
            Commands::FunctionStarts(cmd) => {
                cmd.get_base()
            }
            Commands::LinkerOptHint(cmd) => {
                cmd.get_base()
            }
            Commands::Main(cmd) => {
                cmd.get_base()
            }
            Commands::RPath(cmd) => {
                cmd.get_base()
            }
            Commands::Segment(cmd) => {
                cmd.get_base()
            }
            Commands::SegmentSplitInfo(cmd) => {
                cmd.get_base()
            }
            Commands::SourceVersion(cmd) => {
                cmd.get_base()
            }
            Commands::SubFramework(cmd) => {
                cmd.get_base()
            }
            Commands::SymbolCommand(cmd) => {
                cmd.get_base()
            }
            Commands::ThreadCommand(cmd) => {
                cmd.get_base()
            }
            Commands::TwoLevelHints(cmd) => {
                cmd.get_base()
            }
            Commands::UUID(cmd) => {
                cmd.get_base()
            }
            Commands::VersionMin(cmd) => {
                cmd.get_base()
            }
            Commands::Unknown(cmd) => {
                cmd.get_base()
            }
        }
    }
}

impl Command for Generic<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap()
    }
}

impl std::fmt::Debug for &dyn Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Command")
            .field("offset", &self.offset())
            .field("size", &self.size())
            .field("type", &self.command_type())
            .field("data_len", &self.data().len())
            .finish()
    }
}

declare_iterator!(
    CommandsIter,
    Commands<'a>,
    ffi::MachO_Command,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_commands
);
