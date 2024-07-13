use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::pdb::types::PdbType;
use crate::pdb::types::attribute::Attributes;
use crate::pdb::types::method::Methods;


/// Trait shared by [`Structure`], [`Class`], [`Union`] and [`Interface`]
pub trait ClassLike {
    #[doc(hidden)]
    fn get_classlike(&self) -> &ffi::PDB_types_ClassLike;

    /// Mangled type name
    fn unique_name(&self) -> String {
        self.get_classlike().unique_name().to_string()
    }

    /// Demangled type name
    fn name(&self) -> String {
        self.get_classlike().name().to_string()
    }

    /// Size of the the type including all its attributes. This size should match
    /// the `sizeof(...)` this type.
    fn size(&self) -> u64 {
        self.get_classlike().size()
    }

    /// Iterator over the different [`crate::pdb::types::Attribute`] defined in this
    /// class-like type
    fn attributes(&self) -> Attributes {
        Attributes::new(self.get_classlike().attributes())
    }

    /// Iterator over the different [`crate::pdb::types::Method`] implemented in this
    /// class-like type
    fn methods(&self) -> Methods {
        Methods::new(self.get_classlike().methods())
    }
}

/// This structure wraps a `LF_CLASS` PDB type
pub struct Class<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Class>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Class> for Class<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Class>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl ClassLike for Class<'_> {
    fn get_classlike(&self) -> &ffi::PDB_types_ClassLike {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl PdbType for Class<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

/// This structure wraps a `LF_STRUCTURE` PDB type
pub struct Structure<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Structure>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Structure> for Structure<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Structure>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl ClassLike for Structure<'_> {
    fn get_classlike(&self) -> &ffi::PDB_types_ClassLike {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl PdbType for Structure<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}

/// This structure wraps a `LF_INTERFACE` PDB type
pub struct Interface<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Interface>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Interface> for Interface<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Interface>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl ClassLike for Interface<'_> {
    fn get_classlike(&self) -> &ffi::PDB_types_ClassLike {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl PdbType for Interface<'_> {
    fn get_base(&self) -> &ffi::PDB_Type {
        self.ptr.as_ref().unwrap().as_ref().as_ref()
    }
}
