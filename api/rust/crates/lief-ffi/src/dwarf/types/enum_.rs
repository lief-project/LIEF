#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/Enum.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_Enum;

        #[Self = "DWARF_types_Enum"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn entries(self: &DWARF_types_Enum) -> UniquePtr<DWARF_types_Enum_it_entries>;
        fn underlying_type(self: &DWARF_types_Enum) -> UniquePtr<DWARF_Type>;
        fn find_entry(self: &DWARF_types_Enum, value: i64) -> UniquePtr<DWARF_types_Enum_Entry>;

        type DWARF_types_Enum_Entry;

        fn name(self: &DWARF_types_Enum_Entry) -> UniquePtr<CxxString>;
        fn value(self: &DWARF_types_Enum_Entry, is_set: Pin<&mut u32>) -> i64;

        type DWARF_types_Enum_it_entries;

        fn next(self: Pin<&mut DWARF_types_Enum_it_entries>) -> UniquePtr<DWARF_types_Enum_Entry>;
        fn size(self: &DWARF_types_Enum_it_entries) -> u64;
    }
    impl UniquePtr<DWARF_types_Enum> {}
    impl UniquePtr<DWARF_types_Enum_Entry> {}
    impl UniquePtr<DWARF_types_Enum_it_entries> {}
}
