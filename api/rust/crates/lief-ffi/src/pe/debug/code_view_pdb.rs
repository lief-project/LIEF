#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/PE/debug/CodeViewPDB.hpp");

        type PE_Debug = crate::pe::debug::debug::ffi::PE_Debug;

        type PE_CodeViewPDB;

        #[Self = "PE_CodeViewPDB"]
        fn create() -> UniquePtr<PE_CodeViewPDB>;
        #[Self = "PE_CodeViewPDB"]
        fn create_with_filename(filename: &CxxString) -> UniquePtr<PE_CodeViewPDB>;
        #[Self = "PE_CodeViewPDB"]
        fn classof(entry: &PE_Debug) -> bool;
        fn age(self: &PE_CodeViewPDB) -> u32;
        fn guid(self: &PE_CodeViewPDB) -> UniquePtr<CxxString>;
        fn filename(self: &PE_CodeViewPDB) -> UniquePtr<CxxString>;
        fn signature(self: &PE_CodeViewPDB) -> UniquePtr<CxxVector<u64>>;
        fn set_filename(self: Pin<&mut PE_CodeViewPDB>, filename: &CxxString);
        fn set_age(self: Pin<&mut PE_CodeViewPDB>, age: u32);
        unsafe fn set_signature(self: Pin<&mut PE_CodeViewPDB>, array: *const u8, size: usize);
    }
    impl UniquePtr<PE_CodeViewPDB> {}
}
