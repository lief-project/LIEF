use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::common::into_optional;
use crate::enum_from_int;
use std::marker::PhantomData;

/// This class materializes a scope in which Function, Variable, Type, ...
/// can be defined.
pub struct Scope<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_Scope>,
    _owner: PhantomData<&'a ()>,
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    Type: u32 {
        UNION = 0x00000001,
        CLASS = 0x00000002,
        STRUCT = 0x00000003,
        NAMESPACE = 0x00000004,
        FUNCTION = 0x00000005,
        COMPILATION_UNIT = 0x00000006,
    }
}
impl FromFFI<ffi::DWARF_Scope> for Scope<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_Scope>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Scope<'_> {
    /// Name of the scope. For instance namespace's name or function's name.
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Parent scope (if any)
    pub fn parent(&self) -> Option<Scope<'_>> {
        into_optional(self.ptr.parent())
    }

    /// The current scope type
    pub fn get_type(&self) -> Type {
        Type::from(self.ptr.get_type())
    }

    /// Represent the whole chain of all (parent) scopes using the provided
    /// separator. E.g. `ns1::ns2::Class1::Struct2::Type`
    pub fn chained(&self, sep: &str) -> String {
        cxx::let_cxx_string!(__cxx_s = sep);
        self.ptr.chained(&__cxx_s).to_string()
    }
}
