//! Locations of DWARF variables and parameters (`DW_AT_location`)
//!
//! A location describes where the value of a variable or a parameter lives: in a
//! register, in memory, split across several pieces, ...
use lief_ffi as ffi;
use std::fmt;
use std::marker::PhantomData;

use crate::common::{FromFFI, into_optional};
use crate::{declare_fwd_iterator, to_opt, to_slice};

/// Where the value of a variable or a parameter lives, as described by a DWARF
/// location expression.
pub enum Location<'a> {
    /// The value is associated with a register (e.g. `DW_OP_reg5`)
    Register(RegisterLocation<'a>),

    /// The value is located at a fixed memory address (e.g. `DW_OP_addr`)
    Address(AddressLocation<'a>),

    /// The value is located in memory at an offset of the frame base
    /// (e.g. `DW_OP_fbreg`)
    FrameBase(FrameBaseLocation<'a>),

    /// The value is located in memory at an offset of a register
    /// (e.g. `DW_OP_breg7 +8`)
    RegisterOffset(RegisterOffsetLocation<'a>),

    /// A DWARF expression that is not evaluated by LIEF
    Expression(ExpressionLocation<'a>),

    /// The value is not available (e.g. optimized out)
    Unavailable(UnavailableLocation<'a>),

    /// The value is split into several pieces (`DW_OP_piece/DW_OP_bit_piece`)
    Composite(CompositeLocation<'a>),

    /// A location that is not recognized
    Unknown(UnknownLocation<'a>),
}

impl Location<'_> {
    fn base(&self) -> &ffi::DWARF_Location {
        match self {
            Location::Register(l) => l.ptr.as_ref().unwrap().as_ref(),
            Location::Address(l) => l.ptr.as_ref().unwrap().as_ref(),
            Location::FrameBase(l) => l.ptr.as_ref().unwrap().as_ref(),
            Location::RegisterOffset(l) => l.ptr.as_ref().unwrap().as_ref(),
            Location::Expression(l) => l.ptr.as_ref().unwrap().as_ref(),
            Location::Unavailable(l) => l.ptr.as_ref().unwrap().as_ref(),
            Location::Composite(l) => l.ptr.as_ref().unwrap().as_ref(),
            Location::Unknown(l) => l.ptr.as_ref().unwrap(),
        }
    }
}

impl fmt::Display for Location<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.base().to_string())
    }
}

macro_rules! cast_location {
    ($ptr: expr, $to: ty) => {{
        type From = cxx::UniquePtr<ffi::DWARF_Location>;
        type To = cxx::UniquePtr<$to>;
        unsafe { std::mem::transmute::<From, To>($ptr) }
    }};
}

impl FromFFI<ffi::DWARF_Location> for Location<'_> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::DWARF_Location>) -> Self {
        let loc_ref = ffi_entry.as_ref().unwrap();
        if ffi::DWARF_RegisterLocation::classof(loc_ref) {
            Location::Register(RegisterLocation::from_ffi(cast_location!(
                ffi_entry,
                ffi::DWARF_RegisterLocation
            )))
        } else if ffi::DWARF_AddressLocation::classof(loc_ref) {
            Location::Address(AddressLocation::from_ffi(cast_location!(
                ffi_entry,
                ffi::DWARF_AddressLocation
            )))
        } else if ffi::DWARF_FrameBaseLocation::classof(loc_ref) {
            Location::FrameBase(FrameBaseLocation::from_ffi(cast_location!(
                ffi_entry,
                ffi::DWARF_FrameBaseLocation
            )))
        } else if ffi::DWARF_RegisterOffsetLocation::classof(loc_ref) {
            Location::RegisterOffset(RegisterOffsetLocation::from_ffi(cast_location!(
                ffi_entry,
                ffi::DWARF_RegisterOffsetLocation
            )))
        } else if ffi::DWARF_ExpressionLocation::classof(loc_ref) {
            Location::Expression(ExpressionLocation::from_ffi(cast_location!(
                ffi_entry,
                ffi::DWARF_ExpressionLocation
            )))
        } else if ffi::DWARF_UnavailableLocation::classof(loc_ref) {
            Location::Unavailable(UnavailableLocation::from_ffi(cast_location!(
                ffi_entry,
                ffi::DWARF_UnavailableLocation
            )))
        } else if ffi::DWARF_CompositeLocation::classof(loc_ref) {
            Location::Composite(CompositeLocation::from_ffi(cast_location!(
                ffi_entry,
                ffi::DWARF_CompositeLocation
            )))
        } else {
            Location::Unknown(UnknownLocation::from_ffi(ffi_entry))
        }
    }
}

macro_rules! declare_location {
    ($(#[$meta:meta])* $name: ident, $ffi: ty) => {
        $(#[$meta])*
        pub struct $name<'a> {
            ptr: cxx::UniquePtr<$ffi>,
            _owner: PhantomData<&'a ()>,
        }

        impl FromFFI<$ffi> for $name<'_> {
            fn from_ffi(ptr: cxx::UniquePtr<$ffi>) -> Self {
                Self {
                    ptr,
                    _owner: PhantomData,
                }
            }
        }
    };
}

declare_location!(
    /// The value is associated to a register
    RegisterLocation,
    ffi::DWARF_RegisterLocation
);

impl RegisterLocation<'_> {
    /// DWARF id of the register (e.g. `5` for `DW_OP_reg5`) that must be
    /// interpreted according to the target architecture
    pub fn id(&self) -> u64 {
        self.ptr.id()
    }
}

declare_location!(
    /// The value is located at a fixed memory address
    AddressLocation,
    ffi::DWARF_AddressLocation
);

impl AddressLocation<'_> {
    /// Memory address where the value is located
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }
}

declare_location!(
    /// The value is located in memory relative to the (stack) frame base
    FrameBaseLocation,
    ffi::DWARF_FrameBaseLocation
);

impl FrameBaseLocation<'_> {
    /// Signed byte offset from the frame base
    pub fn offset(&self) -> i64 {
        self.ptr.offset()
    }
}

declare_location!(
    /// The value is located in memory at the address stored in a register plus
    /// a signed offset
    RegisterOffsetLocation,
    ffi::DWARF_RegisterOffsetLocation
);

impl RegisterOffsetLocation<'_> {
    /// DWARF id of the register that contains the base address
    pub fn id(&self) -> u64 {
        self.ptr.id()
    }

    /// Signed byte offset added to the register's value
    pub fn offset(&self) -> i64 {
        self.ptr.offset()
    }
}

declare_location!(
    /// A DWARF expression that is not evaluated by LIEF: implicit values,
    /// computed addresses, entry values, ...
    ExpressionLocation,
    ffi::DWARF_ExpressionLocation
);

impl ExpressionLocation<'_> {
    /// Raw bytes of the DWARF expression
    pub fn expression(&self) -> &[u8] {
        to_slice!(self.ptr.expression());
    }

    /// Textual representation of the expression
    /// (e.g. `DW_OP_lit0, DW_OP_stack_value`)
    pub fn description(&self) -> String {
        self.ptr.description().to_string()
    }
}

declare_location!(
    /// The value is not available at this location (e.g. optimized out)
    UnavailableLocation,
    ffi::DWARF_UnavailableLocation
);

declare_location!(
    /// A location that is not recognized by LIEF
    UnknownLocation,
    ffi::DWARF_Location
);

declare_location!(
    /// The value is split into several pieces, each one with its own location.
    ///
    /// For instance, a 16-bytes structure passed in the `rdi` and `rsi` registers
    /// is described with two 8-bytes pieces.
    CompositeLocation,
    ffi::DWARF_CompositeLocation
);

impl CompositeLocation<'_> {
    /// The pieces of this location, ordered by their bit offset
    pub fn pieces(&self) -> Pieces<'_> {
        Pieces::new(self.ptr.pieces())
    }
}

/// Whether a [`Piece`] comes from `DW_OP_piece` or `DW_OP_bit_piece`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PieceKind {
    /// `DW_OP_piece`
    Byte,
    /// `DW_OP_bit_piece`
    Bit,
    /// A kind that is not recognized
    Unknown(u8),
}

impl From<u8> for PieceKind {
    fn from(value: u8) -> Self {
        match value {
            0 => PieceKind::Byte,
            1 => PieceKind::Bit,
            _ => PieceKind::Unknown(value),
        }
    }
}

/// A piece of a [`CompositeLocation`]
pub struct Piece<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_CompositeLocation_Piece>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_CompositeLocation_Piece> for Piece<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_CompositeLocation_Piece>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Piece<'_> {
    /// Whether this piece comes from `DW_OP_piece` or `DW_OP_bit_piece`
    pub fn kind(&self) -> PieceKind {
        PieceKind::from(self.ptr.kind())
    }

    /// Size of this piece in bits
    pub fn bit_size(&self) -> u64 {
        self.ptr.bit_size()
    }

    /// Offset (in bits) of this piece within the whole value
    pub fn bit_offset(&self) -> u64 {
        self.ptr.bit_offset()
    }

    /// For a `DW_OP_bit_piece`, the offset (in bits) of this piece within its
    /// location (e.g. the register)
    pub fn source_bit_offset(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::DWARF_CompositeLocation_Piece::source_bit_offset,
            &self
        );
    }

    /// Location of this piece or `None` if it can't be decoded
    pub fn location(&self) -> Option<Location<'_>> {
        into_optional(self.ptr.location())
    }
}

/// A [`Location`] associated with the range of addresses where it is valid.
pub struct LocationEntry<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_LocationEntry>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_LocationEntry> for LocationEntry<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_LocationEntry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl LocationEntry<'_> {
    /// Range of addresses `[low, high)` where the location is valid.
    pub fn range(&self) -> Option<crate::Range> {
        let mut is_set: u32 = 0;
        let range = self.ptr.range(std::pin::Pin::new(&mut is_set));
        if is_set == 0 {
            return None;
        }
        Some(crate::Range::from_ffi(&range))
    }

    /// Index of the object's section containing the range (if any)
    pub fn section_index(&self) -> Option<u64> {
        to_opt!(&lief_ffi::DWARF_LocationEntry::section_index, &self);
    }

    /// The location or `None` if the DWARF expression can't be decoded
    pub fn location(&self) -> Option<Location<'_>> {
        into_optional(self.ptr.location())
    }
}

impl fmt::Display for LocationEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

declare_fwd_iterator!(
    Pieces,
    Piece<'a>,
    ffi::DWARF_CompositeLocation_Piece,
    ffi::DWARF_CompositeLocation,
    ffi::DWARF_CompositeLocation_it_pieces
);

declare_fwd_iterator!(
    LocationEntries,
    LocationEntry<'a>,
    ffi::DWARF_LocationEntry,
    ffi::DWARF_LocationEntry,
    ffi::DWARF_it_locations
);
