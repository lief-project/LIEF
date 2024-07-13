use lief_ffi as ffi;

use crate::common::into_optional;
use crate::common::FromFFI;
use std::marker::PhantomData;

/// This class materializes a scope in which Function, Variable, Type, ...
/// can be defined.
pub struct Scope<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_Scope>,
    _owner: PhantomData<&'a ()>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    UNION,
    CLASS,
    STRUCT,
    NAMESPACE,
    FUNCTION,
    COMPILATION_UNIT,
    UNKNOWN(u32),
}

impl From<u32> for Type {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Type::UNION,
            0x00000002 => Type::CLASS,
            0x00000003 => Type::STRUCT,
            0x00000004 => Type::NAMESPACE,
            0x00000005 => Type::FUNCTION,
            0x00000006 => Type::COMPILATION_UNIT,
            _ => Type::UNKNOWN(value),

        }
    }
}
impl From<Type> for u32 {
    fn from(value: Type) -> u32 {
        match value {
            Type::UNION => 0x00000001,
            Type::CLASS => 0x00000002,
            Type::STRUCT => 0x00000003,
            Type::NAMESPACE => 0x00000004,
            Type::FUNCTION => 0x00000005,
            Type::COMPILATION_UNIT => 0x00000006,
            Type::UNKNOWN(_) => 0,

        }
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
    pub fn parent(&self) -> Option<Scope> {
        into_optional(self.ptr.parent())
    }

    /// The current scope type
    pub fn get_type(&self) -> Type {
        Type::from(self.ptr.get_type())
    }

    /// Represent the whole chain of all (parent) scopes using the provided
    /// separator. E.g. `ns1::ns2::Class1::Struct2::Type`
    pub fn chained(&self, sep: &str) -> String {
        self.ptr.chained(sep).to_string()
    }
}

