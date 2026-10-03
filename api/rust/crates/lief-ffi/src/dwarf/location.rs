#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/Location.hpp");

        type Range = crate::utils::ffi::Range;
        type Span = crate::utils::ffi::Span;

        type DWARF_Location;

        fn get_type(self: &DWARF_Location) -> u8;
        fn to_string(self: &DWARF_Location) -> UniquePtr<CxxString>;

        type DWARF_RegisterLocation;

        #[Self = "DWARF_RegisterLocation"]
        fn classof(loc: &DWARF_Location) -> bool;
        fn id(self: &DWARF_RegisterLocation) -> u64;

        type DWARF_AddressLocation;

        #[Self = "DWARF_AddressLocation"]
        fn classof(loc: &DWARF_Location) -> bool;
        fn address(self: &DWARF_AddressLocation) -> u64;

        type DWARF_FrameBaseLocation;

        #[Self = "DWARF_FrameBaseLocation"]
        fn classof(loc: &DWARF_Location) -> bool;
        fn offset(self: &DWARF_FrameBaseLocation) -> i64;

        type DWARF_RegisterOffsetLocation;

        #[Self = "DWARF_RegisterOffsetLocation"]
        fn classof(loc: &DWARF_Location) -> bool;
        fn id(self: &DWARF_RegisterOffsetLocation) -> u64;
        fn offset(self: &DWARF_RegisterOffsetLocation) -> i64;

        type DWARF_ExpressionLocation;

        #[Self = "DWARF_ExpressionLocation"]
        fn classof(loc: &DWARF_Location) -> bool;
        fn expression(self: &DWARF_ExpressionLocation) -> Span;
        fn description(self: &DWARF_ExpressionLocation) -> UniquePtr<CxxString>;

        type DWARF_UnavailableLocation;

        #[Self = "DWARF_UnavailableLocation"]
        fn classof(loc: &DWARF_Location) -> bool;

        type DWARF_CompositeLocation;

        #[Self = "DWARF_CompositeLocation"]
        fn classof(loc: &DWARF_Location) -> bool;
        fn pieces(self: &DWARF_CompositeLocation) -> UniquePtr<DWARF_CompositeLocation_it_pieces>;

        type DWARF_CompositeLocation_Piece;

        fn kind(self: &DWARF_CompositeLocation_Piece) -> u8;
        fn bit_size(self: &DWARF_CompositeLocation_Piece) -> u64;
        fn bit_offset(self: &DWARF_CompositeLocation_Piece) -> u64;
        fn source_bit_offset(self: &DWARF_CompositeLocation_Piece, is_set: Pin<&mut u32>) -> u64;
        fn location(self: &DWARF_CompositeLocation_Piece) -> UniquePtr<DWARF_Location>;

        type DWARF_CompositeLocation_it_pieces;

        fn next(
            self: Pin<&mut DWARF_CompositeLocation_it_pieces>,
        ) -> UniquePtr<DWARF_CompositeLocation_Piece>;
        fn size(self: &DWARF_CompositeLocation_it_pieces) -> u64;

        type DWARF_LocationEntry;

        fn range(self: &DWARF_LocationEntry, is_set: Pin<&mut u32>) -> Range;
        fn section_index(self: &DWARF_LocationEntry, is_set: Pin<&mut u32>) -> u64;
        fn location(self: &DWARF_LocationEntry) -> UniquePtr<DWARF_Location>;
        fn to_string(self: &DWARF_LocationEntry) -> UniquePtr<CxxString>;

        type DWARF_it_locations;

        fn next(self: Pin<&mut DWARF_it_locations>) -> UniquePtr<DWARF_LocationEntry>;
        fn size(self: &DWARF_it_locations) -> u64;
    }

    impl UniquePtr<DWARF_Location> {}
    impl UniquePtr<DWARF_RegisterLocation> {}
    impl UniquePtr<DWARF_AddressLocation> {}
    impl UniquePtr<DWARF_FrameBaseLocation> {}
    impl UniquePtr<DWARF_RegisterOffsetLocation> {}
    impl UniquePtr<DWARF_ExpressionLocation> {}
    impl UniquePtr<DWARF_UnavailableLocation> {}
    impl UniquePtr<DWARF_CompositeLocation> {}
    impl UniquePtr<DWARF_CompositeLocation_Piece> {}
    impl UniquePtr<DWARF_CompositeLocation_it_pieces> {}
    impl UniquePtr<DWARF_LocationEntry> {}
    impl UniquePtr<DWARF_it_locations> {}
}
