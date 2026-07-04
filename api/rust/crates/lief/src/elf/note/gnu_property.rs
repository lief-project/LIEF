use lief_ffi as ffi;
use std::marker::PhantomData;

use super::properties::{Properties, PropertyType};
use super::NoteBase;
use crate::common::{into_optional, FromFFI};
use crate::declare_fwd_iterator;

/// Note representing a GNU Property (`NT_GNU_PROPERTY_TYPE_0`)
pub struct NoteGnuProperty<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl NoteGnuProperty<'_> {
    /// Return the properties as an iterator
    pub fn properties(&self) -> PropertiesIt<'_> {
        PropertiesIt::new(self.ptr.properties())
    }

    /// Find a property by its type
    pub fn find(&self, prop_type: PropertyType) -> Option<Properties<'_>> {
        into_optional(self.ptr.find(prop_type.into()))
    }
}

impl NoteBase for NoteGnuProperty<'_> {
    fn get_base(&self) -> &ffi::ELF_Note {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_NoteGnuProperty> for NoteGnuProperty<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_NoteGnuProperty>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for NoteGnuProperty<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn NoteBase;
        f.debug_struct("NoteGnuProperty")
            .field("base", &base)
            .finish()
    }
}

declare_fwd_iterator!(
    PropertiesIt,
    Properties<'a>,
    ffi::ELF_NoteGnuProperty_Property,
    ffi::ELF_NoteGnuProperty,
    ffi::ELF_NoteGnuProperty_it_properties
);
