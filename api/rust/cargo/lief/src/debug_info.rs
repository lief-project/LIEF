use lief_ffi as ffi;

use crate::pdb;
use crate::dwarf;
use crate::common::FromFFI;

/// This enum wraps either a PDB or a DWARF debug info
pub enum DebugInfo<'a> {
    Pdb(pdb::DebugInfo<'a>),
    Dwarf(dwarf::DebugInfo<'a>),
}

impl FromFFI<ffi::AbstracDebugInfo> for DebugInfo<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::AbstracDebugInfo>) -> Self {
        unsafe {
            let info_ref = info.as_ref().unwrap();

            if ffi::PDB_DebugInfo::classof(info_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::AbstracDebugInfo>;
                    type To = cxx::UniquePtr<ffi::PDB_DebugInfo>;
                    std::mem::transmute::<From, To>(info)
                };
                return DebugInfo::Pdb(pdb::DebugInfo::from_ffi(raw));
            }

            if !ffi::DWARF_DebugInfo::classof(info_ref) {
                panic!("Expecting a DWARF debug info");
            }
            let raw = {
                type From = cxx::UniquePtr<ffi::AbstracDebugInfo>;
                type To = cxx::UniquePtr<ffi::DWARF_DebugInfo>;
                std::mem::transmute::<From, To>(info)
            };
            DebugInfo::Dwarf(dwarf::DebugInfo::from_ffi(raw))
        }
    }
}
