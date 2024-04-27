use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::to_slice;
use crate::common::FromFFI;

use super::{Signature, SignerInfo};

#[derive(Debug)]
pub enum Attribute<'a> {
    ContentType(ContentType<'a>),
    GenericType(GenericType<'a>),
    MsSpcNestedSignature(MsSpcNestedSignature<'a>),
    MsSpcStatementType(MsSpcStatementType<'a>),
    PKCS9AtSequenceNumber(PKCS9AtSequenceNumber<'a>),
    PKCS9CounterSignature(PKCS9CounterSignature<'a>),
    PKCS9MessageDigest(PKCS9MessageDigest<'a>),
    PKCS9SigningTime(PKCS9SigningTime<'a>),
    SpcSpOpusInfo(SpcSpOpusInfo<'a>),
}

impl<'a> FromFFI<ffi::PE_Attribute> for Attribute<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_Attribute>) -> Self {
        unsafe {
            let cmd_ref = ffi_entry.as_ref().unwrap();

            if ffi::PE_ContentType::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_ContentType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::ContentType(ContentType::from_ffi(raw))
            } else if ffi::PE_MsSpcNestedSignature::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_MsSpcNestedSignature>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::MsSpcNestedSignature(MsSpcNestedSignature::from_ffi(raw))
            } else if ffi::PE_MsSpcStatementType::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_MsSpcStatementType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::MsSpcStatementType(MsSpcStatementType::from_ffi(raw))
            } else if ffi::PE_PKCS9AtSequenceNumber::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_PKCS9AtSequenceNumber>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::PKCS9AtSequenceNumber(PKCS9AtSequenceNumber::from_ffi(raw))
            } else if ffi::PE_PKCS9CounterSignature::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_PKCS9CounterSignature>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::PKCS9CounterSignature(PKCS9CounterSignature::from_ffi(raw))
            } else if ffi::PE_PKCS9MessageDigest::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_PKCS9MessageDigest>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::PKCS9MessageDigest(PKCS9MessageDigest::from_ffi(raw))
            } else if ffi::PE_PKCS9SigningTime::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_PKCS9SigningTime>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::PKCS9SigningTime(PKCS9SigningTime::from_ffi(raw))
            } else if ffi::PE_SpcSpOpusInfo::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_SpcSpOpusInfo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::SpcSpOpusInfo(SpcSpOpusInfo::from_ffi(raw))
            } else {
                assert!(
                    ffi::PE_GenericType::classof(cmd_ref),
                    "Must be a GenericType node"
                );
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_GenericType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::GenericType(GenericType::from_ffi(raw))
            }
        }
    }
}

pub struct ContentType<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ContentType>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for ContentType<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentType")
            .field("oid", &self.oid())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ContentType> for ContentType<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ContentType>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}


impl ContentType<'_> {
    pub fn oid(&self) -> String {
        self.ptr.oid().to_string()
    }
}

pub struct GenericType<'a> {
    ptr: cxx::UniquePtr<ffi::PE_GenericType>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for GenericType<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenericType")
            .field("oid", &self.oid())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_GenericType> for GenericType<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_GenericType>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl GenericType<'_> {
    pub fn oid(&self) -> String {
        self.ptr.oid().to_string()
    }

}

pub struct MsSpcNestedSignature<'a> {
    ptr: cxx::UniquePtr<ffi::PE_MsSpcNestedSignature>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for MsSpcNestedSignature<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsSpcNestedSignature").finish()
    }
}

impl<'a> FromFFI<ffi::PE_MsSpcNestedSignature> for MsSpcNestedSignature<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_MsSpcNestedSignature>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}


impl MsSpcNestedSignature<'_> {
    pub fn signature(&self) -> Signature {
        Signature::from_ffi(self.ptr.sig())
    }
}

pub struct MsSpcStatementType<'a> {
    ptr: cxx::UniquePtr<ffi::PE_MsSpcStatementType>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for MsSpcStatementType<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsSpcStatementType")
            .field("oid", &self.oid())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_MsSpcStatementType> for MsSpcStatementType<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_MsSpcStatementType>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}


impl MsSpcStatementType<'_> {
    pub fn oid(&self) -> String {
        self.ptr.oid().to_string()
    }

}

pub struct PKCS9AtSequenceNumber<'a> {
    ptr: cxx::UniquePtr<ffi::PE_PKCS9AtSequenceNumber>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for PKCS9AtSequenceNumber<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKCS9AtSequenceNumber")
            .field("number", &self.number())
            .finish()
    }
}


impl PKCS9AtSequenceNumber<'_> {
    pub fn number(&self) -> u32 {
        self.ptr.number()
    }
}

impl<'a> FromFFI<ffi::PE_PKCS9AtSequenceNumber> for PKCS9AtSequenceNumber<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_PKCS9AtSequenceNumber>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub struct PKCS9CounterSignature<'a> {
    ptr: cxx::UniquePtr<ffi::PE_PKCS9CounterSignature>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for PKCS9CounterSignature<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKCS9CounterSignature").finish()
    }
}

impl<'a> FromFFI<ffi::PE_PKCS9CounterSignature> for PKCS9CounterSignature<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_PKCS9CounterSignature>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl PKCS9CounterSignature<'_> {
    pub fn signer(&self) -> SignerInfo {
        SignerInfo::from_ffi(self.ptr.signer())
    }

}

pub struct PKCS9MessageDigest<'a> {
    ptr: cxx::UniquePtr<ffi::PE_PKCS9MessageDigest>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for PKCS9MessageDigest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKCS9MessageDigest").finish()
    }
}


impl PKCS9MessageDigest<'_> {
    pub fn digest(&self) -> &[u8] {
        to_slice!(self.ptr.digest());
    }
}

impl<'a> FromFFI<ffi::PE_PKCS9MessageDigest> for PKCS9MessageDigest<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_PKCS9MessageDigest>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub struct PKCS9SigningTime<'a> {
    ptr: cxx::UniquePtr<ffi::PE_PKCS9SigningTime>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for PKCS9SigningTime<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKCS9SigningTime")
            .field("time", &self.time())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_PKCS9SigningTime> for PKCS9SigningTime<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_PKCS9SigningTime>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}


impl PKCS9SigningTime<'_> {
    pub fn time(&self) -> Vec<u64> {
        Vec::from(self.ptr.time().as_slice())
    }
}

pub struct SpcSpOpusInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_SpcSpOpusInfo>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for SpcSpOpusInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpcSpOpusInfo")
            .field("program_name", &self.program_name())
            .field("more_info", &self.more_info())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_SpcSpOpusInfo> for SpcSpOpusInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_SpcSpOpusInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl SpcSpOpusInfo<'_> {
    pub fn program_name(&self) -> String {
        self.ptr.program_name().to_string()
    }
    pub fn more_info(&self) -> String {
        self.ptr.more_info().to_string()
    }
}
