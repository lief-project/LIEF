#[repr(C)]
pub struct LIEFVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub id: u64,
}

unsafe impl cxx::ExternType for LIEFVersion {
    type Id = cxx::type_id!("LIEFVersion");
    type Kind = cxx::kind::Trivial;
}

#[repr(C)]
pub struct Span {
    pub ptr: *mut u8,
    pub size: u64,
}

unsafe impl cxx::ExternType for Span {
    type Id = cxx::type_id!("Span");
    type Kind = cxx::kind::Trivial;
}

pub struct Range {
    pub low: u64,
    pub high: u64,
}

unsafe impl cxx::ExternType for Range {
    type Id = cxx::type_id!("Range");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/utils.hpp");

        type LIEFVersion = crate::utils::LIEFVersion;

        type Span = crate::utils::Span;

        type Range = crate::utils::Range;

        fn is_extended() -> bool;

        fn extended_version_info() -> UniquePtr<CxxString>;

        fn extended_version() -> LIEFVersion;

        fn version() -> LIEFVersion;

        fn demangle(mangled: &CxxString, err: Pin<&mut u32>) -> UniquePtr<CxxString>;

        unsafe fn dump(buffer: *const u8, size: usize) -> UniquePtr<CxxString>;

        unsafe fn dump_with_limit(
            buffer: *const u8,
            size: usize,
            limit: u64,
        ) -> UniquePtr<CxxString>;
    }
}
