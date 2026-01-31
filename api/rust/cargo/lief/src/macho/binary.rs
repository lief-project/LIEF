use std::mem::size_of;
use std::pin::Pin;
use std::path::Path;
use num_traits::{Num, cast};

use crate::Error;
use super::builder::Config;
use super::commands::build_version::{BuildVersion, Platform};
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
use super::commands::atom_info::AtomInfo;
use super::commands::function_variants::FunctionVariants;
use super::commands::function_variant_fixups::FunctionVariantFixups;
use super::commands::main_cmd::Main;
use super::commands::note::Note;
use super::commands::rpath::RPath;
use super::commands::routine::Routine;
use super::commands::segment::Segments;
use super::commands::segment_split_info::SegmentSplitInfo;
use super::commands::source_version::SourceVersion;
use super::commands::sub_framework::SubFramework;
use super::commands::sub_client::SubClients;
use super::commands::symbol_command::SymbolCommand;
use super::commands::thread_command::ThreadCommand;
use super::commands::two_level_hints::TwoLevelHints;
use super::commands::uuid::UUID;
use super::commands::version_min::VersionMin;
use super::commands::{CommandsIter, Dylib};
use super::header::Header;
use super::relocation::Relocations;
use super::section::Sections;
use super::symbol::Symbols;
use super::binding_info::BindingInfo;
use super::stub::Stub;
use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use crate::{generic, declare_fwd_iterator, declare_iterator, to_conv_result};
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
    pub fn header(&self) -> Header<'_> {
        Header::from_ffi(self.ptr.header())
    }

    /// Return an iterator over the different [`crate::macho::Commands`] used by the
    /// Mach-O binary
    pub fn commands(&self) -> CommandsIter<'_> {
        CommandsIter::new(self.ptr.commands())
    }

    /// Return an iterator over the different [`crate::macho::Section`] of the binary
    pub fn sections(&self) -> Sections<'_> {
        Sections::new(self.ptr.sections())
    }

    /// Return an iterator over the different [`crate::macho::commands::Segment`] (`LC_SEGMENT/LC_SIGNATURE`)
    /// of the binary.
    pub fn segments(&self) -> Segments<'_> {
        Segments::new(self.ptr.segments())
    }

    /// Return an iterator over the [`crate::macho::commands::Dylib`] used by this binary
    pub fn libraries(&self) -> Libraries<'_> {
        Libraries::new(self.ptr.libraries())
    }

    /// Return an iterator over the different [`crate::macho::Relocation`] of this binary
    pub fn relocations(&self) -> Relocations<'_> {
        Relocations::new(self.ptr.relocations())
    }

    /// Return an iterator over the different [`crate::macho::Symbol`] of this binary
    pub fn symbols(&self) -> Symbols<'_> {
        Symbols::new(self.ptr.symbols())
    }

    /// Return the `LC_DYLD_INFO/LC_DYLD_INFO_ONLY` command if present
    pub fn dyld_info(&self) -> Option<DyldInfo<'_>> {
        into_optional(self.ptr.dyld_info())
    }

    /// Return the `LC_UUID` command if present
    pub fn uuid(&self) -> Option<UUID<'_>> {
        into_optional(self.ptr.uuid())
    }

    /// Return the `LC_MAIN` command if present
    pub fn main_command(&self) -> Option<Main<'_>> {
        into_optional(self.ptr.main_command())
    }

    /// Return the `LC_LOAD_DYLINKER/LC_ID_DYLINKER` command if present
    pub fn dylinker(&self) -> Option<Dylinker<'_>> {
        into_optional(self.ptr.dylinker())
    }

    /// Return the `LC_FUNCTION_STARTS` command if present
    pub fn function_starts(&self) -> Option<FunctionStarts<'_>> {
        into_optional(self.ptr.function_starts())
    }

    /// Return the `LC_SOURCE_VERSION` command if present
    pub fn source_version(&self) -> Option<SourceVersion<'_>> {
        into_optional(self.ptr.source_version())
    }

    /// Return the `LC_THREAD/LC_UNIXTHREAD` command if present
    pub fn thread_command(&self) -> Option<ThreadCommand<'_>> {
        into_optional(self.ptr.thread_command())
    }

    /// Return the `LC_RPATH` command if present
    pub fn rpath(&self) -> Option<RPath<'_>> {
        into_optional(self.ptr.rpath())
    }

    /// Return the `LC_ROUTINE/LC_ROUTINE64` command if present
    pub fn routine(&self) -> Option<Routine<'_>> {
        into_optional(self.ptr.routine_command())
    }

    /// Return the `LC_SYMTAB` command if present
    pub fn symbol_command(&self) -> Option<SymbolCommand<'_>> {
        into_optional(self.ptr.symbol_command())
    }

    /// Return the `LC_DYSYMTAB` command if present
    pub fn dynamic_symbol(&self) -> Option<DynamicSymbolCommand<'_>> {
        into_optional(self.ptr.dynamic_symbol_command())
    }

    /// Return the `LC_CODE_SIGNATURE` command if present
    pub fn code_signature(&self) -> Option<CodeSignature<'_>> {
        into_optional(self.ptr.code_signature())
    }

    /// Return the `LC_DYLIB_CODE_SIGN_DRS` command if present
    pub fn code_signature_dir(&self) -> Option<CodeSignatureDir<'_>> {
        into_optional(self.ptr.code_signature_dir())
    }

    /// Return the `LC_DATA_IN_CODE` command if present
    pub fn data_in_code(&self) -> Option<DataInCode<'_>> {
        into_optional(self.ptr.data_in_code())
    }

    /// Return the `LC_SEGMENT_SPLIT_INFO` command if present
    pub fn segment_split_info(&self) -> Option<SegmentSplitInfo<'_>> {
        into_optional(self.ptr.segment_split_info())
    }

    /// Return the `LC_ENCRYPTION_INFO/LC_ENCRYPTION_INFO_64` command if present
    pub fn encryption_info(&self) -> Option<EncryptionInfo<'_>> {
        into_optional(self.ptr.encryption_info())
    }

    /// Return the `LC_SUB_FRAMEWORK` command if present
    pub fn sub_framework(&self) -> Option<SubFramework<'_>> {
        into_optional(self.ptr.sub_framework())
    }

    /// Return the `LC_SUBCLIENT` command if present
    pub fn subclients(&self) -> SubClients<'_> {
        SubClients::new(self.ptr.subclients())
    }

    /// Return the `LC_DYLD_ENVIRONMENT` command if present
    pub fn dyld_environment(&self) -> Option<DyldEnvironment<'_>> {
        into_optional(self.ptr.dyld_environment())
    }

    /// Return the `LC_BUILD_VERSION` command if present
    pub fn build_version(&self) -> Option<BuildVersion<'_>> {
        into_optional(self.ptr.build_version())
    }

    /// Return the `LC_DYLD_CHAINED_FIXUPS` command if present
    pub fn dyld_chained_fixups(&self) -> Option<DyldChainedFixups<'_>> {
        into_optional(self.ptr.dyld_chained_fixups())
    }

    /// Return the `LC_DYLD_EXPORTS_TRIE` command if present
    pub fn dyld_exports_trie(&self) -> Option<DyldExportsTrie<'_>> {
        into_optional(self.ptr.dyld_exports_trie())
    }

    /// Return the `LC_TWOLEVEL_HINTS` command if present
    pub fn two_level_hints(&self) -> Option<TwoLevelHints<'_>> {
        into_optional(self.ptr.two_level_hints())
    }

    /// Return the `LC_LINKER_OPTIMIZATION_HINT` command if present
    pub fn linker_opt_hint(&self) -> Option<LinkerOptHint<'_>> {
        into_optional(self.ptr.linker_opt_hint())
    }

    /// Return the `LC_ATOM_INFO` command if present
    pub fn atom_info(&self) -> Option<AtomInfo<'_>> {
        into_optional(self.ptr.atom_info())
    }

    /// Return the `LC_FUNCTION_VARIANTS` command if present
    pub fn function_variants(&self) -> Option<FunctionVariants<'_>> {
        into_optional(self.ptr.function_variants())
    }

    /// Return the `LC_FUNCTION_VARIANT_FIXUPS` command if present
    pub fn function_variant_fixups(&self) -> Option<FunctionVariantFixups<'_>> {
        into_optional(self.ptr.function_variant_fixups())
    }

    /// Return the `LC_VERSION_MIN_MACOSX/VERSION_MIN_IPHONEOS` command if present
    pub fn version_min(&self) -> Option<VersionMin<'_>> {
        into_optional(self.ptr.version_min())
    }

    /// Check if the binary is supporting ARM64 pointer authentication (arm64e)
    pub fn support_arm64_ptr_auth(&self) -> bool {
        self.ptr.support_arm64_ptr_auth()
    }

    /// Return an iterator over the bindings located in [`DyldInfo`] or [`DyldChainedFixups`]
    pub fn bindings(&self) -> BindingsInfo<'_> {
        BindingsInfo::new(self.ptr.bindings())
    }

    /// Return an iterator over the symbol stubs.
    ///
    /// These stubs are involved when calling an **imported** function and are
    /// similar to the ELF's plt/got mechanism.
    ///
    /// There are located in sections like: `__stubs,__auth_stubs,__symbol_stub,__picsymbolstub4`
    pub fn symbol_stubs(&self) -> Stubs<'_> {
        Stubs::new(self.ptr.symbol_stubs())
    }

    /// Return Objective-C metadata if present
    pub fn objc_metadata(&self) -> Option<Metadata<'_>> {
        into_optional(self.ptr.objc_metadata())
    }

    /// Return the platform for which this Mach-O has been compiled for
    pub fn platform(&self) -> Platform {
        Platform::from(self.ptr.platform())
    }

    /// True if this binary targets iOS
    pub fn is_ios(&self) -> bool {
        self.ptr.is_ios()
    }

    /// True if this binary targets macOS
    pub fn is_macos(&self) -> bool {
        self.ptr.is_macos()
    }

    /// Try to find the library with the given library name.
    ///
    /// This function tries to match the fullpath of the DylibCommand or the
    /// library name suffix.
    pub fn find_library(&self, name: &str) -> Option<Dylib<'_>> {
        into_optional(self.ptr.find_library(name.to_string()))
    }


    /// Get the integer value at the given virtual address
    pub fn get_int_from_virtual_address<T>(&self, addr: u64) -> Result<T, Error>
        where T: Num + cast::FromPrimitive + cast::ToPrimitive
    {
        // Can't be in the generic trait because of:
        //   > for a trait to be "object safe" it needs to allow building a vtable to allow the call
        //   > to be resolvable dynamically; for more information visit
        //   > https://doc.rust-lang.org/reference/items/traits.html#object-safety
        if size_of::<T>() == size_of::<u8>() {
            to_conv_result!(ffi::AbstractBinary::get_u8,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| { T::from_u8(value).unwrap_or_else(|| panic!("Can't cast value: {value}")) },
                addr);
        }

        if size_of::<T>() == size_of::<u16>() {
            to_conv_result!(ffi::AbstractBinary::get_u16,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| { T::from_u16(value).unwrap_or_else(|| panic!("Can't cast value: {value}")) },
                addr);
        }

        if size_of::<T>() == size_of::<u32>() {
            to_conv_result!(ffi::AbstractBinary::get_u32,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| { T::from_u32(value).unwrap_or_else(|| panic!("Can't cast value: {value}")) },
                addr);
        }

        if size_of::<T>() == size_of::<u64>() {
            to_conv_result!(ffi::AbstractBinary::get_u64,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| { T::from_u64(value).unwrap_or_else(|| panic!("Can't cast value: {value}")) },
                addr);
        }

        Err(Error::NotSupported)
    }

    /// Write back the current MachO binary into the file specified in parameter
    pub fn write<P: AsRef<Path>>(&mut self, output: P) {
        self.ptr.as_mut().unwrap().write(output.as_ref().to_str().unwrap());
    }

    /// Write back the current MachO binary into the file specified in parameter with the
    /// configuration provided in the second parameter.
    pub fn write_with_config<P: AsRef<Path>>(&mut self, output: P, config: Config) {
        self.ptr.as_mut().unwrap().write_with_config(output.as_ref().to_str().unwrap(), config.to_ffi());
    }

    /// Insert a new shared library through a `LC_LOAD_DYLIB` command
    pub fn add_library<'a>(&'a mut self, libname: &str) -> Dylib<'a> {
        Dylib::from_ffi(self.ptr.as_mut().unwrap().add_library(libname))
    }

    pub fn functions(&self) -> generic::Functions<'_> {
        generic::Functions::new(self.ptr.functions())
    }

    /// Return an iterator over the `LC_NOTE` commands
    pub fn notes(&self) -> Notes<'_> {
        Notes::new(self.ptr.notes())
    }
}

impl generic::Binary for Binary {
    fn as_generic(&self) -> &ffi::AbstractBinary {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_pin_mut_generic(&mut self) -> Pin<&mut ffi::AbstractBinary> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref()
                    as *const ffi::AbstractBinary
                    as *mut ffi::AbstractBinary).as_mut().unwrap()
            })
        }
    }
}

declare_fwd_iterator!(
    BindingsInfo,
    BindingInfo<'a>,
    ffi::MachO_BindingInfo,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_bindings_info
);

declare_iterator!(
    Stubs,
    Stub<'a>,
    ffi::MachO_Stub,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_stubs
);

declare_iterator!(
    Notes,
    Note<'a>,
    ffi::MachO_NoteCommand,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_notes
);
