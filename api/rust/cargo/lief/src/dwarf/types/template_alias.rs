use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::dwarf::Type;
use crate::declare_fwd_iterator;
use crate::dwarf::Parameters;

/// This structure represents a `DW_TAG_template_alias`
pub struct TemplateAlias<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_TemplateAlias>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_TemplateAlias> for TemplateAlias<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_TemplateAlias>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for TemplateAlias<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl TemplateAlias<'_> {
    /// The underlying type aliased by this type.
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }

    /// [`Parameters`] associated with the underlying template
    pub fn parameters(&self) -> ParametersIt {
        ParametersIt::new(self.ptr.parameters())
    }
}

declare_fwd_iterator!(
    ParametersIt,
    Parameters<'a>,
    ffi::DWARF_Parameter,
    ffi::DWARF_types_TemplateAlias,
    ffi::DWARF_types_TemplateAlias_it_parameters
);
