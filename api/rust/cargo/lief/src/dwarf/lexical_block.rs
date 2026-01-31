use lief_ffi as ffi;

use crate::common::{FromFFI, into_ranges};
use crate::{Range, declare_fwd_iterator, to_opt};
use std::marker::PhantomData;

/// This structure represents a DWARF lexical block (`DW_TAG_lexical_block`)
pub struct LexicalBlock<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_LexicalBlock>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_LexicalBlock> for LexicalBlock<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_LexicalBlock>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl LexicalBlock<'_> {
    /// Return the *name* associated with this lexical block or an empty string
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Return the description associated with this lexical block or an empty string
    pub fn description(&self) -> String {
        self.ptr.description().to_string()
    }

    /// Return an iterator over the sub-LexicalBlock owned by this block.
    pub fn sub_blocks(&self) -> LexicalBlocks<'_> {
        LexicalBlocks::new(self.ptr.sub_blocks())
    }

    /// Return the start address of this block
    pub fn addr(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::DWARF_LexicalBlock::addr,
            &self
        );
    }

    /// Return the lowest virtual address owned by this block.
    pub fn low_pc(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::DWARF_LexicalBlock::low_pc,
            &self
        );
    }

    /// Return the highest virtual address owned by this block.
    pub fn high_pc(&self) -> Option<u64> {
        to_opt!(
            &lief_ffi::DWARF_LexicalBlock::high_pc,
            &self
        );
    }


    /// Return the size of this block as the difference of the highest address and the lowest
    /// address.
    pub fn size(&self) -> u64 {
        self.ptr.size()
    }

    /// Return a list of address ranges owned by this block.
    ///
    /// If the lexical block owns a contiguous range, it should return
    /// **a single** range.
    pub fn ranges(&self) -> Vec<Range> {
        into_ranges(self.ptr.ranges())
    }
}

declare_fwd_iterator!(
    LexicalBlocks,
    LexicalBlock<'a>,
    ffi::DWARF_LexicalBlock,
    ffi::DWARF_LexicalBlock,
    ffi::DWARF_LexicalBlock_it_sub_blocks
);
