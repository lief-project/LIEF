#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/logging.hpp");

        type LIEF_Logging;

        #[Self = "LIEF_Logging"]
        fn disable();
        #[Self = "LIEF_Logging"]
        fn reset();
        #[Self = "LIEF_Logging"]
        fn enable();
        #[Self = "LIEF_Logging"]
        fn set_level(lvl: u32);
        #[Self = "LIEF_Logging"]
        fn set_path(path: &CxxString);
        #[Self = "LIEF_Logging"]
        fn log(lvl: u32, msg: &CxxString);
        #[Self = "LIEF_Logging"]
        fn get_level() -> u32;

        type LIEF_Logging_Scoped;

        #[Self = "LIEF_Logging_Scoped"]
        fn create(lvl: u32) -> UniquePtr<LIEF_Logging_Scoped>;
        fn set_level(self: &LIEF_Logging_Scoped, lvl: u32);
        fn reset(self: Pin<&mut LIEF_Logging_Scoped>);
    }
    impl UniquePtr<LIEF_Logging_Scoped> {}
}
