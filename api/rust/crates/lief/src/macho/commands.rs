use std::marker::PhantomData;

use lief_ffi as ffi;
pub mod atom_info;
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
pub mod fileset;
pub mod function_variant_fixups;
pub mod function_variants;
pub mod functionstarts;
pub mod lazy_load_dylib_info;
pub mod linker_opt_hint;
pub mod main_cmd;
pub mod note;
pub mod routine;
pub mod rpath;
pub mod segment;
pub mod segment_split_info;
pub mod source_version;
pub mod sub_client;
pub mod sub_framework;
pub mod symbol_command;
pub mod thread_command;
pub mod two_level_hints;
pub mod unknown;
pub mod uuid;
pub mod version_min;

#[doc(inline)]
pub use atom_info::AtomInfo;
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
pub use fileset::Fileset;
#[doc(inline)]
pub use function_variant_fixups::FunctionVariantFixups;
#[doc(inline)]
pub use function_variants::FunctionVariants;
#[doc(inline)]
pub use functionstarts::FunctionStarts;
#[doc(inline)]
pub use lazy_load_dylib_info::LazyLoadDylibInfo;
#[doc(inline)]
pub use linker_opt_hint::LinkerOptHint;
#[doc(inline)]
pub use main_cmd::Main;
#[doc(inline)]
pub use note::Note;
#[doc(inline)]
pub use routine::Routine;
#[doc(inline)]
pub use rpath::RPath;
#[doc(inline)]
pub use segment::Segment;
#[doc(inline)]
pub use segment_split_info::SegmentSplitInfo;
#[doc(inline)]
pub use source_version::SourceVersion;
#[doc(inline)]
pub use sub_client::SubClient;
#[doc(inline)]
pub use sub_framework::SubFramework;
#[doc(inline)]
pub use symbol_command::SymbolCommand;
#[doc(inline)]
pub use thread_command::ThreadCommand;
#[doc(inline)]
pub use two_level_hints::TwoLevelHints;
#[doc(inline)]
pub use unknown::Unknown;
#[doc(inline)]
pub use uuid::UUID;
#[doc(inline)]
pub use version_min::VersionMin;

use crate::common::FromFFI;
use crate::{declare_iterator, enum_from_int, to_slice};

enum_from_int! {
    LoadCommandTypes: u64 {
        BuildVersion = 0x00000032,
        CodeSignature = 0x0000001D,
        DataInCode = 0x00000029,
        DyldChainedFixups = 0x80000034,
        DyldEnvironment = 0x00000027,
        DyldExportsTrie = 0x80000033,
        DyldInfo = 0x00000022,
        DyldInfoOnly = 0x80000022,
        DylibCodeSignDrs = 0x0000002B,
        Dysymtab = 0x0000000B,
        EncryptionInfo = 0x00000021,
        EncryptionInfo64 = 0x0000002C,
        FilesetEntry = 0x80000035,
        FunctionStarts = 0x00000026,
        Fvmfile = 0x00000009,
        Ident = 0x00000008,
        Idfvmlib = 0x00000007,
        IdDylib = 0x0000000D,
        IdDylinker = 0x0000000F,
        LazyLoadDylib = 0x00000020,
        LinkerOptimizationHint = 0x0000002E,
        LinkerOption = 0x0000002D,
        LoadFvmLib = 0x00000006,
        LoadDylib = 0x0000000C,
        LoadDylinker = 0x0000000E,
        LoadUpwardDylib = 0x80000023,
        LoadWeakDylib = 0x80000018,
        Main = 0x80000028,
        Note = 0x00000031,
        PrebindCksum = 0x00000017,
        PreboundDylib = 0x00000010,
        Prepage = 0x0000000A,
        ReExportDylib = 0x8000001F,
        Routines = 0x00000011,
        Routines64 = 0x0000001A,
        Rpath = 0x8000001C,
        Segment = 0x00000001,
        Segment64 = 0x00000019,
        SegmentSplitInfo = 0x0000001E,
        SourceVersion = 0x0000002A,
        SubClient = 0x00000014,
        SubFramework = 0x00000012,
        SubLibrary = 0x00000015,
        SubUmbrella = 0x00000013,
        Symseg = 0x00000003,
        Symtab = 0x00000002,
        Thread = 0x00000004,
        TwoLevelHints = 0x00000016,
        Unixthread = 0x00000005,
        Uuid = 0x0000001B,
        VersionMinIphoneOS = 0x00000025,
        VersionMinMacOSX = 0x00000024,
        VersionMinTvOS = 0x0000002F,
        VersionMinWatchOS = 0x00000030,
        AtomInfo = 0x00000036,
        FunctionVariants = 0x00000037,
        FunctionVariantsFixups = 0x00000038,
        TargetTriple = 0x00000039,
        LazyLoadDylibInfo = 0x0000003A,

        LiefUnknown = 0xffee0001,
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
    Fileset(Fileset<'a>),
    FunctionStarts(FunctionStarts<'a>),
    LinkerOptHint(LinkerOptHint<'a>),
    Main(Main<'a>),
    RPath(RPath<'a>),
    Routine(Routine<'a>),
    Segment(Segment<'a>),
    SegmentSplitInfo(SegmentSplitInfo<'a>),
    SourceVersion(SourceVersion<'a>),
    SubFramework(SubFramework<'a>),
    SubClient(SubClient<'a>),
    SymbolCommand(SymbolCommand<'a>),
    ThreadCommand(ThreadCommand<'a>),
    TwoLevelHints(TwoLevelHints<'a>),
    UUID(UUID<'a>),
    VersionMin(VersionMin<'a>),
    AtomInfo(AtomInfo<'a>),
    Note(Note<'a>),
    FunctionVariants(FunctionVariants<'a>),
    FunctionVariantFixups(FunctionVariantFixups<'a>),
    LazyLoadDylibInfo(LazyLoadDylibInfo<'a>),
    Unknown(Unknown<'a>),
}

impl FromFFI<ffi::MachO_Command> for Commands<'_> {
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
            } else if ffi::MachO_Fileset::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_Fileset>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::Fileset(Fileset::from_ffi(raw))
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
            } else if ffi::MachO_Routine::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_Routine>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::Routine(Routine::from_ffi(raw))
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
            } else if ffi::MachO_SubClient::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_SubClient>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::SubClient(SubClient::from_ffi(raw))
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
            } else if ffi::MachO_AtomInfo::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_AtomInfo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::AtomInfo(AtomInfo::from_ffi(raw))
            } else if ffi::MachO_NoteCommand::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_NoteCommand>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::Note(Note::from_ffi(raw))
            } else if ffi::MachO_FunctionVariants::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_FunctionVariants>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::FunctionVariants(FunctionVariants::from_ffi(raw))
            } else if ffi::MachO_FunctionVariantFixups::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_FunctionVariantFixups>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::FunctionVariantFixups(FunctionVariantFixups::from_ffi(raw))
            } else if ffi::MachO_LazyLoadDylibInfo::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_Command>;
                    type To = cxx::UniquePtr<ffi::MachO_LazyLoadDylibInfo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Commands::LazyLoadDylibInfo(LazyLoadDylibInfo::from_ffi(raw))
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

    /// Size of the command (should be greater than ``sizeof(load_command)``)
    fn size(&self) -> u32 {
        self.get_base().size()
    }

    /// Offset of the command within the *Load Command Table*
    fn offset(&self) -> u64 {
        self.get_base().command_offset()
    }

    /// The command's type
    fn command_type(&self) -> LoadCommandTypes {
        LoadCommandTypes::from(self.get_base().cmd_type())
    }

    /// The raw command as a slice of bytes
    fn data(&self) -> &[u8] {
        to_slice!(self.get_base().data());
    }
}

impl Command for Commands<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        match &self {
            Commands::Generic(cmd) => cmd.get_base(),
            Commands::BuildVersion(cmd) => cmd.get_base(),
            Commands::CodeSignature(cmd) => cmd.get_base(),
            Commands::CodeSignatureDir(cmd) => cmd.get_base(),
            Commands::DataInCode(cmd) => cmd.get_base(),
            Commands::DyldChainedFixups(cmd) => cmd.get_base(),
            Commands::DyldEnvironment(cmd) => cmd.get_base(),
            Commands::DyldExportsTrie(cmd) => cmd.get_base(),
            Commands::DyldInfo(cmd) => cmd.get_base(),
            Commands::Dylib(cmd) => cmd.get_base(),
            Commands::Dylinker(cmd) => cmd.get_base(),
            Commands::DynamicSymbolCommand(cmd) => cmd.get_base(),
            Commands::EncryptionInfo(cmd) => cmd.get_base(),
            Commands::FunctionStarts(cmd) => cmd.get_base(),
            Commands::LinkerOptHint(cmd) => cmd.get_base(),
            Commands::Main(cmd) => cmd.get_base(),
            Commands::Routine(cmd) => cmd.get_base(),
            Commands::RPath(cmd) => cmd.get_base(),
            Commands::Segment(cmd) => cmd.get_base(),
            Commands::SegmentSplitInfo(cmd) => cmd.get_base(),
            Commands::SourceVersion(cmd) => cmd.get_base(),
            Commands::SubFramework(cmd) => cmd.get_base(),
            Commands::SubClient(cmd) => cmd.get_base(),
            Commands::SymbolCommand(cmd) => cmd.get_base(),
            Commands::ThreadCommand(cmd) => cmd.get_base(),
            Commands::TwoLevelHints(cmd) => cmd.get_base(),
            Commands::UUID(cmd) => cmd.get_base(),
            Commands::VersionMin(cmd) => cmd.get_base(),
            Commands::AtomInfo(cmd) => cmd.get_base(),
            Commands::Note(cmd) => cmd.get_base(),
            Commands::FunctionVariants(cmd) => cmd.get_base(),
            Commands::FunctionVariantFixups(cmd) => cmd.get_base(),
            Commands::LazyLoadDylibInfo(cmd) => cmd.get_base(),
            Commands::Fileset(cmd) => cmd.get_base(),
            Commands::Unknown(cmd) => cmd.get_base(),
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
