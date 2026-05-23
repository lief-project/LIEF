#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/DWARF/types/Array.hpp");

        type DWARF_Type = crate::dwarf::type_::ffi::DWARF_Type;

        type DWARF_types_Array;

        #[Self = "DWARF_types_Array"]
        fn classof(type_: &DWARF_Type) -> bool;
        fn underlying_type(self: &DWARF_types_Array) -> UniquePtr<DWARF_Type>;
        fn size_info(self: &DWARF_types_Array) -> UniquePtr<DWARF_types_array_size_info>;

        type DWARF_types_array_size_info;

        fn name(self: &DWARF_types_array_size_info) -> UniquePtr<CxxString>;
        fn size(self: &DWARF_types_array_size_info) -> u64;
        fn get_type(self: &DWARF_types_array_size_info) -> UniquePtr<DWARF_Type>;
    }
    impl UniquePtr<DWARF_types_Array> {}
    impl UniquePtr<DWARF_types_array_size_info> {}
}
