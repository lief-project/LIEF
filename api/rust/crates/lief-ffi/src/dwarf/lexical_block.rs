#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/LexicalBlock.hpp");

        type Range = crate::utils::ffi::Range;
        type DWARF_LexicalBlock;

        fn ranges(self: &DWARF_LexicalBlock) -> UniquePtr<CxxVector<Range>>;
        fn name(self: &DWARF_LexicalBlock) -> UniquePtr<CxxString>;
        fn description(self: &DWARF_LexicalBlock) -> UniquePtr<CxxString>;
        fn addr(self: &DWARF_LexicalBlock, is_set: Pin<&mut u32>) -> u64;
        fn low_pc(self: &DWARF_LexicalBlock, is_set: Pin<&mut u32>) -> u64;
        fn high_pc(self: &DWARF_LexicalBlock, is_set: Pin<&mut u32>) -> u64;
        fn size(self: &DWARF_LexicalBlock) -> u64;
        fn sub_blocks(self: &DWARF_LexicalBlock) -> UniquePtr<DWARF_LexicalBlock_it_sub_blocks>;

        type DWARF_LexicalBlock_it_sub_blocks;

        fn next(self: Pin<&mut DWARF_LexicalBlock_it_sub_blocks>) -> UniquePtr<DWARF_LexicalBlock>;
        fn size(self: &DWARF_LexicalBlock_it_sub_blocks) -> u64;
    }
    impl UniquePtr<DWARF_LexicalBlock> {}
    impl UniquePtr<DWARF_LexicalBlock_it_sub_blocks> {}
}
