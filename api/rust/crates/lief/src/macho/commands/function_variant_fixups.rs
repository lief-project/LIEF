use super::Command;
use super::Segment;
use crate::common::{into_optional, FromFFI};
use crate::{declare_iterator, to_slice};
use lief_ffi as ffi;
use std::marker::PhantomData;

/// Structure which represents the `LC_FUNCTION_VARIANT_FIXUPS` command.
///
/// This command contains the relocations that must be applied to the GOT-like
/// slots associated with a [`crate::macho::commands::FunctionVariants`] table.
/// At runtime, `dyld` resolves each slot to the best implementation and
/// (re-)signs it according to the pointer-authentication information.
pub struct FunctionVariantFixups<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_FunctionVariantFixups>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl FunctionVariantFixups<'_> {
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

    /// Iterator over the different [`Fixup`] entries
    pub fn fixups(&self) -> Fixups<'_> {
        Fixups::new(self.ptr.fixups())
    }
}

impl std::fmt::Debug for FunctionVariantFixups<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("FunctionVariantFixups")
            .field("base", &base)
            .field("data_offset", &self.data_offset())
            .field("data_size", &self.data_size())
            .finish()
    }
}

impl FromFFI<ffi::MachO_FunctionVariantFixups> for FunctionVariantFixups<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_FunctionVariantFixups>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for FunctionVariantFixups<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

/// A single relocation associated with a function-variant. It mirrors the
/// `FunctionVariantFixups::InternalFixup` structure used by `dyld` and
/// describes a slot that must be fixed up to point to the variant referenced by
/// [`Fixup::variant_index`].
pub struct Fixup<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_FunctionVariantFixups_Fixup>,
    _owner: PhantomData<&'a ffi::MachO_FunctionVariantFixups>,
}

impl FromFFI<ffi::MachO_FunctionVariantFixups_Fixup> for Fixup<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_FunctionVariantFixups_Fixup>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Fixup<'_> {
    /// Offset of the slot to fix up, relative to the segment designated by
    /// [`Fixup::seg_index`]
    pub fn seg_offset(&self) -> u32 {
        self.ptr.seg_offset()
    }

    /// Index of the segment that owns the slot to fix up
    pub fn seg_index(&self) -> u32 {
        self.ptr.seg_index()
    }

    /// Index of the FunctionVariants runtime table used to resolve the slot
    pub fn variant_index(&self) -> u32 {
        self.ptr.variant_index()
    }

    /// Whether the slot is signed with pointer authentication (arm64e)
    pub fn pac_auth(&self) -> bool {
        self.ptr.pac_auth()
    }

    /// Whether the pointer-authentication signature mixes the storage address
    /// (address diversity)
    pub fn pac_address(&self) -> bool {
        self.ptr.pac_address()
    }

    /// Pointer-authentication key used to sign the slot
    pub fn pac_key(&self) -> u8 {
        self.ptr.pac_key()
    }

    /// Pointer-authentication diversity (discriminator) of the slot
    pub fn pac_diversity(&self) -> u16 {
        self.ptr.pac_diversity()
    }

    /// [`Segment`] referenced by [`Fixup::seg_index`] if it could be resolved
    pub fn segment(&self) -> Option<Segment<'_>> {
        into_optional(self.ptr.segment())
    }
}

impl std::fmt::Debug for Fixup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fixup")
            .field("seg_offset", &self.seg_offset())
            .field("seg_index", &self.seg_index())
            .field("variant_index", &self.variant_index())
            .field("pac_auth", &self.pac_auth())
            .field("pac_address", &self.pac_address())
            .field("pac_key", &self.pac_key())
            .field("pac_diversity", &self.pac_diversity())
            .finish()
    }
}

impl std::fmt::Display for Fixup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

declare_iterator!(
    Fixups,
    Fixup<'a>,
    ffi::MachO_FunctionVariantFixups_Fixup,
    ffi::MachO_FunctionVariantFixups,
    ffi::MachO_FunctionVariantFixups_it_fixups
);
