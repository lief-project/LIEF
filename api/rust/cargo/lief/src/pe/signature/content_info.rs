use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use crate::to_slice;
use crate::pe::Algorithms;

pub struct ContentInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ContentInfo>,
    _owner: PhantomData<&'a ffi::PE_Signature>,
}

/// ContentInfo as described in the RFC2315 <https://tools.ietf.org/html/rfc2315#section-7>
impl ContentInfo<'_> {
    /// Return the OID that describes the content wrapped by this object.
    /// It should match `SPC_INDIRECT_DATA_OBJID` (`1.3.6.1.4.1.311.2.1.4`)
    pub fn content_type(&self) -> String {
        self.ptr.content_type().to_string()
    }

    pub fn value(&self) -> Option<Content<'_>> {
        into_optional(self.ptr.value())
    }

    /// Return the digest (authentihash) if the underlying content type is `SPC_INDIRECT_DATA_OBJID`
    /// Otherwise, return an empty vector
    pub fn digest(&self) -> Vec<u8> {
        Vec::from(self.ptr.digest().as_slice())
    }

    /// Return the digest used to hash the file
    pub fn digest_algorithm(&self) -> Algorithms {
        Algorithms::from(self.ptr.digest_algorithm())
    }
}

impl std::fmt::Debug for ContentInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentInfo")
            .field("content_type", &self.content_type())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ContentInfo> for ContentInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ContentInfo>) -> Self {
        ContentInfo {
            ptr,
            _owner: PhantomData,
        }
    }
}

#[derive(Debug)]
pub enum Content<'a> {
    SpcIndirectData(SpcIndirectData<'a>),
    PKCS9TSTInfo(PKCS9TSTInfo<'a>),
    Generic(Generic<'a>),
}

impl<'a> FromFFI<ffi::PE_ContentInfo_Content> for Content<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_ContentInfo_Content>) -> Self {
        unsafe {
            let content_ref = ffi_entry.as_ref().unwrap();
            if ffi::PE_SpcIndirectData::classof(content_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_ContentInfo_Content>;
                    type To = cxx::UniquePtr<ffi::PE_SpcIndirectData>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Content::SpcIndirectData(SpcIndirectData::from_ffi(raw))
            }
            else if ffi::PE_PKCS9TSTInfo::classof(content_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_ContentInfo_Content>;
                    type To = cxx::UniquePtr<ffi::PE_PKCS9TSTInfo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Content::PKCS9TSTInfo(PKCS9TSTInfo::from_ffi(raw))
            } else {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_ContentInfo_Content>;
                    type To = cxx::UniquePtr<ffi::PE_GenericContent>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Content::Generic(Generic::from_ffi(raw))
            }
        }
    }
}

pub trait ContentTrait {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::PE_ContentInfo_Content;

    /// Return the OID that describes this content info.
    /// In the case of the PE authenticode, it should return `SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4)`
    fn content_type(&self) -> String {
        self.as_generic().content_type().to_string()
    }
}

pub struct SpcIndirectData<'a> {
    ptr: cxx::UniquePtr<ffi::PE_SpcIndirectData>,
    _owner: PhantomData<&'a ffi::PE_ContentInfo>,
}

impl SpcIndirectData<'_> {
    pub fn file(&self) -> String {
        self.ptr.file().to_string()
    }
    /// PE's authentihash
    ///
    /// See: [`crate::pe::Binary::authentihash`]
    pub fn digest(&self) -> &[u8] {
        to_slice!(self.ptr.digest());
    }

    /// Digest used to hash the file
    pub fn digest_algorithm(&self) -> Algorithms {
        Algorithms::from(self.ptr.digest_algorithm())
    }
}

impl std::fmt::Debug for SpcIndirectData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpcIndirectData")
            .field("file", &self.file())
            .field("digest_algorithm", &self.digest_algorithm())
            .finish()
    }
}

impl FromFFI<ffi::PE_SpcIndirectData> for SpcIndirectData<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PE_SpcIndirectData>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl ContentTrait for SpcIndirectData<'_> {
    fn as_generic(&self) -> &ffi::PE_ContentInfo_Content {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

pub struct PKCS9TSTInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_PKCS9TSTInfo>,
    _owner: PhantomData<&'a ffi::PE_ContentInfo>,
}

impl PKCS9TSTInfo<'_> {
    // TODO(romain): Add API
}

impl std::fmt::Debug for PKCS9TSTInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKCS9TSTInfo")
            .finish()
    }
}

impl FromFFI<ffi::PE_PKCS9TSTInfo> for PKCS9TSTInfo<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PE_PKCS9TSTInfo>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl ContentTrait for PKCS9TSTInfo<'_> {
    fn as_generic(&self) -> &ffi::PE_ContentInfo_Content {
        self.ptr.as_ref().unwrap().as_ref()
    }
}


pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::PE_GenericContent>,
    _owner: PhantomData<&'a ffi::PE_ContentInfo>,
}

impl Generic<'_> {
    pub fn raw(&self) -> &[u8] {
        to_slice!(self.ptr.raw());
    }

    pub fn oid(&self) -> String {
        self.ptr.oid().to_string()
    }

}

impl std::fmt::Debug for Generic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generic").finish()
    }
}

impl FromFFI<ffi::PE_GenericContent> for Generic<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PE_GenericContent>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl ContentTrait for Generic<'_> {
    fn as_generic(&self) -> &ffi::PE_ContentInfo_Content {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

