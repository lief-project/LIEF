use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::generic;
use crate::macho::section::MachOSection;
use std::fmt;
use std::pin::Pin;
use std::marker::PhantomData;

/// This class represents a MachO section whose type is
/// [`crate::macho::section::Type::THREAD_LOCAL_VARIABLES`].
///
/// It contains an array of thread-local variable descriptors ([`Thunk`]) used
/// by dyld to lazily initialize thread-local storage on first access.
pub struct ThreadLocalVariables<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_ThreadLocalVariables>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl ThreadLocalVariables<'_> {
    /// Number of [`Thunk`] descriptors in this section
    pub fn nb_thunks(&self) -> u64 {
        self.ptr.nb_thunks().try_into().unwrap()
    }

    /// Iterator over the [`Thunk`] descriptors stored in this section
    pub fn thunks(&self) -> Thunks<'_> {
        Thunks::new(self.ptr.thunks())
    }

    /// Return the [`Thunk`] at the given index, or `None` if out of range.
    pub fn get(&self, idx: u64) -> Option<Thunk<'_>> {
        into_optional(self.ptr.get_thunk(idx))
    }

    /// Change the [`Thunk`] at the given index.
    pub fn set(&mut self, idx: u64, thunk: &Thunk<'_>) {
        self.ptr.pin_mut().set_thunk(idx, thunk.func(), thunk.key(), thunk.offset());
    }
}

impl fmt::Debug for ThreadLocalVariables<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadLocalVariables")
            .field("nb_thunks", &self.nb_thunks())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_ThreadLocalVariables> for ThreadLocalVariables<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_ThreadLocalVariables>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl generic::Section for ThreadLocalVariables<'_> {
    fn as_generic(&self) -> &ffi::AbstractSection {
        self.as_base().as_ref()
    }

    fn as_generic_mut(&mut self) -> Pin<&mut ffi::AbstractSection> {
        unsafe {
            Pin::new_unchecked({
                (self.as_generic() as *const ffi::AbstractSection
                    as *mut ffi::AbstractSection)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}


impl MachOSection for ThreadLocalVariables<'_> {
    fn as_base(&self) -> &ffi::MachO_Section {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_mut_base(&mut self) -> Pin<&mut ffi::MachO_Section> {
        unsafe {
            Pin::new_unchecked({
                (self.as_base() as *const ffi::MachO_Section
                    as *mut ffi::MachO_Section)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}


/// Descriptor for a single thread-local variable.
///
/// The layout mirrors the `tlv_descriptor` structure from `<mach-o/loader.h>`.
pub struct Thunk<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_ThreadLocalVariables_Thunk>,
    _owner: PhantomData<&'a ffi::MachO_ThreadLocalVariables>,
}

impl Thunk<'_> {
    /// Address of the initializer function (`tlv_thunk`)
    pub fn func(&self) -> u64 {
        self.ptr.func()
    }

    /// `pthread_key_t` key used by the runtime
    pub fn key(&self) -> u64 {
        self.ptr.key()
    }

    /// Offset of the variable in the TLS block
    pub fn offset(&self) -> u64 {
        self.ptr.offset()
    }
}

impl fmt::Debug for Thunk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Thunk")
            .field("func", &format_args!("{:#x}", self.func()))
            .field("key", &format_args!("{:#x}", self.key()))
            .field("offset", &format_args!("{:#x}", self.offset()))
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_ThreadLocalVariables_Thunk> for Thunk<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_ThreadLocalVariables_Thunk>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

declare_iterator!(
    Thunks,
    Thunk<'a>,
    ffi::MachO_ThreadLocalVariables_Thunk,
    ffi::MachO_ThreadLocalVariables,
    ffi::MachO_ThreadLocalVariables_it_thunks
);
