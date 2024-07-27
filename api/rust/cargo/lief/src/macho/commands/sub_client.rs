use super::Command;
use lief_ffi as ffi;
use crate::declare_iterator;
use crate::common::FromFFI;

use std::marker::PhantomData;

/// Class that represents the SubClient command.
/// Accodring to the Mach-O `loader.h` documentation:
///
/// > For dynamically linked shared libraries that are subframework of an umbrella
/// > framework they can allow clients other than the umbrella framework or other
/// > subframeworks in the same umbrella framework.  To do this the subframework
/// > is built with "-allowable_client client_name" and an LC_SUB_CLIENT load
/// > command is created for each -allowable_client flag.  The client_name is
/// > usually a framework name.  It can also be a name used for bundles clients
/// > where the bundle is built with "-client_name client_name".
pub struct SubClient<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_SubClient>,
    _owner: PhantomData<&'a ffi::MachO_Binary>
}


impl SubClient<'_> {
    /// Name of the subclient
    pub fn client(&self) -> String {
        self.ptr.client().to_string()
    }
}

impl std::fmt::Debug for SubClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("SubClient")
            .field("base", &base)
            .field("client", &self.client())
            .finish()
    }
}

impl FromFFI<ffi::MachO_SubClient> for SubClient<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_SubClient>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData
        }
    }
}

impl Command for SubClient<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_iterator!(
    SubClients,
    SubClient<'a>,
    ffi::MachO_SubClient,
    ffi::MachO_Binary,
    ffi::MachO_Binary_it_sub_clients
);
