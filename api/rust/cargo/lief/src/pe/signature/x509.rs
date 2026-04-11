use std::marker::PhantomData;

use bitflags::bitflags;
use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use crate::declare_iterator;
use crate::pe::Algorithms;

use super::RsaInfo;

/// Structure for a x509 certificate
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
/// Public key scheme
pub enum KeyType {
    /// Unknown scheme
    NONE,

    /// RSA Scheme
    RSA,

    /// Elliptic-curve scheme
    ECKEY,

    /// Elliptic-curve Diffie-Hellman
    ECKEY_DH,

    /// Elliptic-curve Digital Signature Algorithm
    ECDSA,

    /// RSA scheme with an alternative implementation for signing and decrypting
    RSA_ALT,

    /// RSA Probabilistic signature scheme
    RSASSA_PSS,
    UNKNOWN(u32),
}

impl From<u32> for KeyType {
    fn from(value: u32) -> Self {
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

/// Key usage as defined in RFC #5280 - section-4.2.1.3
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum KeyUsage {
    /// The key is used for digital signature
    DIGITAL_SIGNATURE,
    /// The key is used for digital signature and to protect against falsely denying some action
    NON_REPUDIATION,
    /// The key is used for enciphering private or secret keys
    KEY_ENCIPHERMENT,
    /// The key is used for directly enciphering raw user data without an intermediate symmetric cipher
    DATA_ENCIPHERMENT,
    /// The key is used for key agreement (e.g. with Diffie-Hellman)
    KEY_AGREEMENT,
    /// The key is used for verifying signatures on public key certificates
    KEY_CERT_SIGN,
    /// The key is used for verifying signatures on certificate revocation lists
    CRL_SIGN,
    /// In association with KEY_AGREEMENT, the key is only used for enciphering data
    ENCIPHER_ONLY,
    /// In association with KEY_AGREEMENT, the key is only used for deciphering data
    DECIPHER_ONLY,
    UNKNOWN(u32),
}

impl From<u32> for KeyUsage {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => KeyUsage::DIGITAL_SIGNATURE,
            0x00000001 => KeyUsage::NON_REPUDIATION,
            0x00000002 => KeyUsage::KEY_ENCIPHERMENT,
            0x00000003 => KeyUsage::DATA_ENCIPHERMENT,
            0x00000004 => KeyUsage::KEY_AGREEMENT,
            0x00000005 => KeyUsage::KEY_CERT_SIGN,
            0x00000006 => KeyUsage::CRL_SIGN,
            0x00000007 => KeyUsage::ENCIPHER_ONLY,
            0x00000008 => KeyUsage::DECIPHER_ONLY,
            _ => KeyUsage::UNKNOWN(value),
        }
    }
}

impl From<KeyUsage> for u32 {
    fn from(value: KeyUsage) -> u32 {
        match value {
            KeyUsage::DIGITAL_SIGNATURE => 0x00000000,
            KeyUsage::NON_REPUDIATION => 0x00000001,
            KeyUsage::KEY_ENCIPHERMENT => 0x00000002,
            KeyUsage::DATA_ENCIPHERMENT => 0x00000003,
            KeyUsage::KEY_AGREEMENT => 0x00000004,
            KeyUsage::KEY_CERT_SIGN => 0x00000005,
            KeyUsage::CRL_SIGN => 0x00000006,
            KeyUsage::ENCIPHER_ONLY => 0x00000007,
            KeyUsage::DECIPHER_ONLY => 0x00000008,
            KeyUsage::UNKNOWN(v) => v,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    /// Mirror of mbedtls X509 verification flags for certificate verification
    pub struct VerificationFlags: u32 {
        const OK = 0;
        const BADCERT_EXPIRED = 1 << 0;
        const BADCERT_REVOKED = 1 << 1;
        const BADCERT_CN_MISMATCH = 1 << 2;
        const BADCERT_NOT_TRUSTED = 1 << 3;
        const BADCRL_NOT_TRUSTED = 1 << 4;
        const BADCRL_EXPIRED = 1 << 5;
        const BADCERT_MISSING = 1 << 6;
        const BADCERT_SKIP_VERIFY = 1 << 7;
        const BADCERT_OTHER = 1 << 8;
        const BADCERT_FUTURE = 1 << 9;
        const BADCRL_FUTURE = 1 << 10;
        const BADCERT_KEY_USAGE = 1 << 11;
        const BADCERT_EXT_KEY_USAGE = 1 << 12;
        const BADCERT_NS_CERT_TYPE = 1 << 13;
        const BADCERT_BAD_MD = 1 << 14;
        const BADCERT_BAD_PK = 1 << 15;
        const BADCERT_BAD_KEY = 1 << 16;
        const BADCRL_BAD_MD = 1 << 17;
        const BADCRL_BAD_PK = 1 << 18;
        const BADCRL_BAD_KEY = 1 << 19;
    }
}

impl std::fmt::Display for VerificationFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl From<u32> for VerificationFlags {
    fn from(value: u32) -> Self {
        VerificationFlags::from_bits_truncate(value)
    }
}

impl From<VerificationFlags> for u32 {
    fn from(value: VerificationFlags) -> Self {
        value.bits()
    }
}

impl VerificationFlags {
    pub fn is_ok(self) -> bool {
        self == VerificationFlags::OK
    }
}

impl X509<'_> {
    /// X.509 version. (1=v1, 2=v2, 3=v3)
    pub fn version(&self) -> u32 {
        self.ptr.version()
    }

    /// Unique id for certificate issued by a specific CA.
    pub fn serial_number(&self) -> Vec<u8> {
        Vec::from(self.ptr.serial_number().as_slice())
    }

    /// Signature algorithm (OID)
    pub fn signature_algorithm(&self) -> String {
        self.ptr.signature_algorithm().to_string()
    }

    /// Start time of certificate validity
    pub fn valid_from(&self) -> Vec<u64> {
        Vec::from(self.ptr.valid_from().as_slice())
    }

    /// End time of certificate validity
    pub fn valid_to(&self) -> Vec<u64> {
        Vec::from(self.ptr.valid_to().as_slice())
    }

    /// Issuer information
    pub fn issuer(&self) -> String {
        self.ptr.issuer().to_string()
    }

    /// Subject information
    pub fn subject(&self) -> String {
        self.ptr.subject().to_string()
    }

    /// The raw x509 bytes (DER encoded)
    pub fn raw(&self) -> Vec<u8> {
        Vec::from(self.ptr.raw().as_slice())
    }

    /// Return the underlying public-key scheme
    pub fn key_type(&self) -> KeyType {
        KeyType::from(self.ptr.key_type())
    }
    pub fn is_ca(&self) -> bool {
        self.ptr.is_ca()
    }

    /// The signature of the certificate
    pub fn signature(&self) -> Vec<u8> {
        Vec::from(self.ptr.signature().as_slice())
    }

    /// **If** the underlying public-key scheme is RSA, return the RSA information.
    pub fn rsa_info(&self) -> Option<RsaInfo<'_>> {
        into_optional(self.ptr.rsa_info())
    }

    /// Try to decrypt the given signature and check if it matches the given hash according to
    /// the hash algorithm provided
    pub fn check_signature(&self, hash: &[u8], signature: &[u8], digest: Algorithms) -> bool {
        unsafe {
            self.ptr.check_signature(
                hash.as_ptr(),
                hash.len(),
                signature.as_ptr(),
                signature.len(),
                digest.into(),
            )
        }
    }

    /// Verify that this certificate has been used **to trust** the given certificate
    pub fn verify(&self, ca: &X509) -> VerificationFlags {
        VerificationFlags::from(self.ptr.verify(ca.ptr.as_ref().unwrap()))
    }

    /// Return the key usage extensions of this certificate
    pub fn key_usage(&self) -> Vec<KeyUsage> {
        self.ptr
            .key_usage()
            .into_iter()
            .map(|e| KeyUsage::from(*e))
            .collect()
    }

    /// Return the extended key usage OIDs of this certificate
    pub fn ext_key_usage(&self) -> Vec<String> {
        self.ptr
            .ext_key_usage()
            .into_iter()
            .map(|e| e.to_string())
            .collect()
    }

    /// Return the certificate policies OIDs of this certificate
    pub fn certificate_policies(&self) -> Vec<String> {
        self.ptr
            .certificate_policies()
            .into_iter()
            .map(|e| e.to_string())
            .collect()
    }
}

declare_iterator!(
    Certificates,
    X509<'a>,
    ffi::PE_x509,
    ffi::PE_Signature,
    ffi::PE_Signature_it_certificates
);
