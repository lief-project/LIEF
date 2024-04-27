use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;

use super::RsaInfo;

pub struct X509<'a> {
    ptr: cxx::UniquePtr<ffi::PE_x509>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for X509<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("x509")
            .field("version", &self.version())
            .field("signature_algorithm", &self.signature_algorithm())
            .field("valid_from", &self.valid_from())
            .field("valid_to", &self.valid_to())
            .field("issuer", &self.issuer())
            .field("key_type", &self.key_type())
            .field("subject", &self.subject())
            .field("is_ca", &self.is_ca())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_x509> for X509<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_x509>) -> Self {
        X509 {
            ptr,
            _owner: PhantomData,
        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum KeyType {
    NONE,
    RSA,
    ECKEY,
    ECKEY_DH,
    ECDSA,
    RSA_ALT,
    RSASSA_PSS,
    UNKNOWN(u32),
}


impl KeyType {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => KeyType::NONE,
            0x00000001 => KeyType::RSA,
            0x00000002 => KeyType::ECKEY,
            0x00000003 => KeyType::ECKEY_DH,
            0x00000004 => KeyType::ECDSA,
            0x00000005 => KeyType::RSA_ALT,
            0x00000006 => KeyType::RSASSA_PSS,
            _ => KeyType::UNKNOWN(value),

        }
    }
}

impl X509<'_> {
    pub fn version(&self) -> u32 {
        self.ptr.version()
    }
    pub fn serial_number(&self) -> Vec<u8> {
        Vec::from(self.ptr.serial_number().as_slice())
    }
    pub fn signature_algorithm(&self) -> String {
        self.ptr.signature_algorithm().to_string()
    }
    pub fn valid_from(&self) -> Vec<u64> {
        Vec::from(self.ptr.valid_from().as_slice())
    }
    pub fn valid_to(&self) -> Vec<u64> {
        Vec::from(self.ptr.valid_to().as_slice())
    }
    pub fn issuer(&self) -> String {
        self.ptr.issuer().to_string()
    }
    pub fn subject(&self) -> String {
        self.ptr.subject().to_string()
    }
    pub fn raw(&self) -> Vec<u8> {
        Vec::from(self.ptr.raw().as_slice())
    }
    pub fn key_type(&self) -> KeyType {
        KeyType::from_value(self.ptr.key_type())
    }
    pub fn is_ca(&self) -> bool {
        self.ptr.is_ca()
    }
    pub fn signature(&self) -> Vec<u8> {
        Vec::from(self.ptr.signature().as_slice())
    }
    pub fn rsa_info(&self) -> Option<RsaInfo> {
        into_optional(self.ptr.rsa_info())
    }
}

declare_iterator!(
    Certificates,
    X509<'a>,
    ffi::PE_x509,
    ffi::PE_Signature,
    ffi::PE_Signature_it_certificates
);
