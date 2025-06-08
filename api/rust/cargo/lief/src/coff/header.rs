
//! COFF section module

use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::pe;
use crate::to_slice;


/// This enum represents the different types of COFF header.
pub enum Header<'a> {
    /// Regular (default) header
    Regular(RegularHeader<'a>),

    /// Header for COFF files that contain more than 65536 sections (compiled with `/bigobj`)
    BigObj(BigObjHeader<'a>),
}

impl FromFFI<ffi::COFF_Header> for Header<'_> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::COFF_Header>) -> Self {
        unsafe {
            let obj_ref = ffi_entry.as_ref().unwrap();
            if ffi::COFF_RegularHeader::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::COFF_Header>;
                    type To = cxx::UniquePtr<ffi::COFF_RegularHeader>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Header::Regular(RegularHeader::from_ffi(raw))
            } else if ffi::COFF_BigObjHeader::classof(obj_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::COFF_Header>;
                    type To = cxx::UniquePtr<ffi::COFF_BigObjHeader>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Header::BigObj(BigObjHeader::from_ffi(raw))
            } else {
                panic!("unsupported header");
            }
        }
    }
}

/// Trait shared by the different COFF headers
pub trait GenericHeader {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::COFF_Header;

    /// The machine type targeted by this COFF
    fn machine(&self) -> pe::headers::MachineType {
        pe::headers::MachineType::from(self.as_generic().machine())
    }

    /// The number of sections
    fn nb_sections(&self) -> u32 {
        self.as_generic().nb_sections()
    }

    /// Offset of the symbols table
    fn pointerto_symbol_table(&self) -> u32 {
        self.as_generic().pointerto_symbol_table()
    }

    /// Number of symbols (including auxiliary symbols)
    fn nb_symbols(&self) -> u32 {
        self.as_generic().nb_symbols()
    }

    /// Timestamp when the COFF has been generated
    fn timedatestamp(&self) -> u32 {
        self.as_generic().timedatestamp()
    }
}

impl GenericHeader for Header<'_> {
    fn as_generic(&self) -> &ffi::COFF_Header {
        match &self {
            Header::Regular(h) => h.as_generic(),
            Header::BigObj(h) => h.as_generic(),
        }
    }
}


impl std::fmt::Debug for &dyn GenericHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenericHeader")
            .field("machine", &self.machine())
            .field("nb_sections", &self.nb_sections())
            .field("pointerto_symbol_table", &self.pointerto_symbol_table())
            .field("nb_symbols", &self.nb_symbols())
            .field("timedatestamp", &self.timedatestamp())
            .finish()
    }
}

impl std::fmt::Display for &dyn GenericHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}


/// Regular (default) header
pub struct RegularHeader<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_RegularHeader>,
    _owner: PhantomData<&'a ffi::COFF_Binary>,
}

impl FromFFI<ffi::COFF_RegularHeader> for RegularHeader<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_RegularHeader>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl RegularHeader<'_> {
    /// The size of the optional header that follows this header (should be 0)
    pub fn sizeof_optionalheader(&self) -> u16 {
        self.ptr.sizeof_optionalheader()
    }

    /// Characteristics
    pub fn characteristics(&self) -> u16 {
        self.ptr.characteristics()
    }
}

impl GenericHeader for RegularHeader<'_> {
    fn as_generic(&self) -> &ffi::COFF_Header {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for RegularHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn GenericHeader;
        f.debug_struct("RegularHeader")
            .field("base", &base)
            .field("sizeof_optionalheader", &self.sizeof_optionalheader())
            .field("characteristics", &self.characteristics())
            .finish()
    }
}

impl std::fmt::Display for RegularHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

/// Header for COFF files that contain more than 65536 sections (compiled with `/bigobj`)
pub struct BigObjHeader<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_BigObjHeader>,
    _owner: PhantomData<&'a ffi::COFF_Binary>,
}

impl FromFFI<ffi::COFF_BigObjHeader> for BigObjHeader<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_BigObjHeader>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl BigObjHeader<'_> {
    /// The version of this header which must be >= 2
    pub fn version(&self) -> u16 {
        self.ptr.version()
    }

    /// Originally named `ClassID`, this uuid should match: `{D1BAA1C7-BAEE-4ba9-AF20-FAF66AA4DCB8}`
    pub fn uuid(&self) -> &[u8] {
        to_slice!(self.ptr.uuid());
    }

    /// Size of data that follows the header
    pub fn sizeof_data(&self) -> u32 {
        self.ptr.sizeof_data()
    }

    /// 1 means that it contains metadata
    pub fn flags(&self) -> u32 {
        self.ptr.flags()
    }

    /// Size of CLR metadata
    pub fn metadata_size(&self) -> u32 {
        self.ptr.metadata_size()
    }

    /// Offset of CLR metadata
    pub fn metadata_offset(&self) -> u32 {
        self.ptr.metadata_offset()
    }
}

impl std::fmt::Debug for BigObjHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn GenericHeader;
        f.debug_struct("BigObjHeader")
            .field("base", &base)
            .field("version", &self.version())
            .field("uuid", &self.uuid())
            .field("sizeof_data", &self.sizeof_data())
            .field("flags", &self.flags())
            .field("metadata_size", &self.metadata_size())
            .field("metadata_offset", &self.metadata_offset())
            .finish()
    }
}


impl GenericHeader for BigObjHeader<'_> {
    fn as_generic(&self) -> &ffi::COFF_Header {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Display for BigObjHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}
