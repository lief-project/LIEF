use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::to_slice;
use crate::pe::Algorithms;
use crate::pe::signature::ContentInfo;
use crate::declare_iterator;
use crate::pe::signature::X509;

use super::{Signature, SignerInfo};

#[derive(Debug)]
/// This enum exposes the different attributes that can be wrapped in
/// a [`crate::pe::signature::SignerInfo`]
pub enum Attribute<'a> {
    /// Attribute for the OID: `1.2.840.113549.1.9.3`
    ContentType(ContentType<'a>),
    /// Attribute for the OID: `1.3.6.1.4.1.311.2.4.1`
    MsSpcNestedSignature(MsSpcNestedSignature<'a>),
    /// Attribute for the OID: `1.3.6.1.4.1.311.2.1.11`
    MsSpcStatementType(MsSpcStatementType<'a>),
    /// Attribute for the OID: `1.2.840.113549.1.9.25.4`
    PKCS9AtSequenceNumber(PKCS9AtSequenceNumber<'a>),
    /// Attribute for the OID: `1.2.840.113549.1.9.6`
    PKCS9CounterSignature(PKCS9CounterSignature<'a>),
    /// Attribute for the OID: `1.2.840.113549.1.9.4`
    PKCS9MessageDigest(PKCS9MessageDigest<'a>),
    /// Attribute for the OID: `1.2.840.113549.1.9.5`
    PKCS9SigningTime(PKCS9SigningTime<'a>),
    /// Attribute for the OID: `1.3.6.1.4.1.311.2.1.12`
    SpcSpOpusInfo(SpcSpOpusInfo<'a>),
    /// Attribute for the OID: `1.3.6.1.4.1.311.10.3.28`
    MsManifestBinaryID(MsManifestBinaryID<'a>),
    /// Attribute for the OID: `1.3.6.1.4.1.311.3.3.1`
    MsCounterSign(MsCounterSign<'a>),
    /// Attribute for the OID: `1.2.840.113549.1.9.16.2.47`
    SigningCertificateV2(SigningCertificateV2<'a>),
    /// Attribute for the OID: `1.3.6.1.4.1.311.2.6.1`
    SpcRelaxedPeMarkerCheck(SpcRelaxedPeMarkerCheck<'a>),
    /// Attribute for an OID not supported by LIEF
    GenericType(GenericType<'a>),
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
            } else if ffi::PE_MsManifestBinaryID::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_MsManifestBinaryID>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::MsManifestBinaryID(MsManifestBinaryID::from_ffi(raw))
            } else if ffi::PE_MsCounterSign::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_MsCounterSign>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::MsCounterSign(MsCounterSign::from_ffi(raw))
            } else if ffi::PE_SpcRelaxedPeMarkerCheck::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_SpcRelaxedPeMarkerCheck>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::SpcRelaxedPeMarkerCheck(SpcRelaxedPeMarkerCheck::from_ffi(raw))
            } else if ffi::PE_SigningCertificateV2::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_Attribute>;
                    type To = cxx::UniquePtr<ffi::PE_SigningCertificateV2>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Attribute::SigningCertificateV2(SigningCertificateV2::from_ffi(raw))
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
/// Interface over the structure described by the OID ``1.2.840.113549.1.9.3`` (PKCS #9)
///
/// The internal structure is described in the RFC #2985
///
/// ```text
/// ContentType ::= OBJECT IDENTIFIER
/// ```
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
    /// OID as described in RFC #2985
    pub fn oid(&self) -> String {
        self.ptr.oid().to_string()
    }
}

/// Interface over an attribute for which the internal structure is not supported by LIEF
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
    /// OID of the original attribute
    pub fn oid(&self) -> String {
        self.ptr.oid().to_string()
    }

    /// Original DER blob of the attribute
    pub fn raw_content(&self) -> &[u8] {
        to_slice!(self.ptr.raw_content());
    }
}

/// Interface over the structure described by the OID `1.3.6.1.4.1.311.2.4.1`
///
/// The internal structure is not documented but we can infer the following structure:
///
/// ```text
/// MsSpcNestedSignature ::= SET OF SignedData
/// ```
///
/// `SignedData` is the structure described in PKCS #7 RFC
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
    /// Underlying Signature object
    pub fn signature(&self) -> Signature {
        Signature::from_ffi(self.ptr.sig())
    }
}

/// Interface over the structure described by the OID `1.3.6.1.4.1.311.2.1.11`
///
/// The internal structure is described in the official document:
/// *Windows Authenticode Portable Executable Signature Format*
///
/// ```text
/// SpcStatementType ::= SEQUENCE of OBJECT IDENTIFIER
/// ```
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
    /// According to the documentation:
    /// > The SpcStatementType MUST contain one Object Identifier with either
    /// > the value `1.3.6.1.4.1.311.2.1.21 (SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID)` or
    /// > `1.3.6.1.4.1.311.2.1.22 (SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID)`.
    pub fn oid(&self) -> String {
        self.ptr.oid().to_string()
    }
}

/// Interface over the structure described by the OID `1.2.840.113549.1.9.25.4` (PKCS #9)
///
/// The internal structure is described in the
/// RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0
///
/// ```text
/// sequenceNumber ATTRIBUTE ::= {
///   WITH SYNTAX SequenceNumber
///   EQUALITY MATCHING RULE integerMatch
///   SINGLE VALUE TRUE
///   ID pkcs-9-at-sequenceNumber
/// }
///
/// SequenceNumber ::= INTEGER (1..MAX)
/// ```
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
    //! Number as described in the RFC
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

/// Interface over the structure described by the OID `1.2.840.113549.1.9.6` (PKCS #9)
///
/// The internal structure is described in the
/// RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0
///
/// ```text
/// counterSignature ATTRIBUTE ::= {
///   WITH SYNTAX SignerInfo
///   ID pkcs-9-at-counterSignature
/// }
/// ```
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
    /// SignerInfo as described in the RFC #2985
    pub fn signer(&self) -> SignerInfo {
        SignerInfo::from_ffi(self.ptr.signer())
    }
}

/// Interface over the structure described by the OID `1.2.840.113549.1.9.4` (PKCS #9)
///
/// The internal structure is described in the
/// RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0
///
/// ```text
/// messageDigest ATTRIBUTE ::= {
///   WITH SYNTAX MessageDigest
///   EQUALITY MATCHING RULE octetStringMatch
///   SINGLE VALUE TRUE
///   ID pkcs-9-at-messageDigest
/// }
///
/// MessageDigest ::= OCTET STRING
/// ```
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
    /// Message digeset as a blob of bytes as described in the RFC
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

/// Interface over the structure described by the OID `1.2.840.113549.1.9.5` (PKCS #9)
///
/// The internal structure is described in the
/// RFC #2985: PKCS #9 - Selected Object Classes and Attribute Types Version 2.0
///
/// ```text
/// signingTime ATTRIBUTE ::= {
///         WITH SYNTAX SigningTime
///         EQUALITY MATCHING RULE signingTimeMatch
///         SINGLE VALUE TRUE
///         ID pkcs-9-at-signingTime
/// }
///
/// SigningTime ::= Time -- imported from ISO/IEC 9594-8
/// ```
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
    /// Time as a tuple: `(year, month, day, hour, min, sec)`
    pub fn time(&self) -> (u64, u64, u64, u64, u64, u64) {
        let vec = Vec::from(self.ptr.time().as_slice());
        if vec.len() != 6 {
            return (0, 0, 0, 0, 0, 0);
        }
        (vec[0], vec[1], vec[2], vec[3], vec[4], vec[5])
    }
}

/// Interface over the structure described by the OID `1.3.6.1.4.1.311.2.1.12`
///
/// The internal structure is described in the official document:
/// *Windows Authenticode Portable Executable Signature Format*
///
/// ```text
/// SpcSpOpusInfo ::= SEQUENCE {
///     programName  [0] EXPLICIT SpcString OPTIONAL,
///     moreInfo     [1] EXPLICIT SpcLink OPTIONAL
/// }
/// ```
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
    /// Program description provided by the publisher
    pub fn program_name(&self) -> String {
        self.ptr.program_name().to_string()
    }

    /// Other information such as an url
    pub fn more_info(&self) -> String {
        self.ptr.more_info().to_string()
    }
}

pub struct SpcRelaxedPeMarkerCheck<'a> {
    ptr: cxx::UniquePtr<ffi::PE_SpcRelaxedPeMarkerCheck>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for SpcRelaxedPeMarkerCheck<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpcRelaxedPeMarkerCheck")
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_SpcRelaxedPeMarkerCheck> for SpcRelaxedPeMarkerCheck<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_SpcRelaxedPeMarkerCheck>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl SpcRelaxedPeMarkerCheck<'_> {

}


/// ```text
/// SigningCertificateV2 ::= SEQUENCE {
///   certs    SEQUENCE OF ESSCertIDv2,
///   policies SEQUENCE OF PolicyInformation OPTIONAL
/// }
///
/// ESSCertIDv2 ::= SEQUENCE {
///   hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
///   certHash      OCTET STRING,
///   issuerSerial  IssuerSerial OPTIONAL
/// }
///
/// IssuerSerial ::= SEQUENCE {
///   issuer       GeneralNames,
///   serialNumber CertificateSerialNumber
/// }
///
/// PolicyInformation ::= SEQUENCE {
///   policyIdentifier   OBJECT IDENTIFIER,
///   policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
/// }
/// ```
pub struct SigningCertificateV2<'a> {
    ptr: cxx::UniquePtr<ffi::PE_SigningCertificateV2>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for SigningCertificateV2<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningCertificateV2")
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_SigningCertificateV2> for SigningCertificateV2<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_SigningCertificateV2>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl SigningCertificateV2<'_> {
    // TODO(romain): Add API
}

/// This structure exposes the MS Counter Signature attribute
pub struct MsCounterSign<'a> {
    ptr: cxx::UniquePtr<ffi::PE_MsCounterSign>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for MsCounterSign<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsCounterSign")
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_MsCounterSign> for MsCounterSign<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_MsCounterSign>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> MsCounterSign<'a> {
    pub fn version(&self) -> u32 {
        self.ptr.version()
    }

    pub fn digest_algorithm(&self) -> Algorithms {
        Algorithms::from(self.ptr.digest_algorithm())
    }

    /// ContentInfo as described in the RFC2315 <https://tools.ietf.org/html/rfc2315#section-7>
    pub fn content_info(&'a self) -> ContentInfo<'a> {
        ContentInfo::from_ffi(self.ptr.content_info())
    }

    /// Return list of [`crate::pe::X509`] certificates associated with this signature
    pub fn certificates(&'a self) -> MsCounterCertificates<'a> {
        MsCounterCertificates::new(self.ptr.certificates())
    }

    /// Iterator over the signer [`SignerInfo`] defined in the PKCS #7 signature
    pub fn signers(&'a self) -> MsCounterSigners<'a> {
        MsCounterSigners::new(self.ptr.signers())
    }
}

declare_iterator!(
    MsCounterCertificates,
    X509<'a>,
    ffi::PE_x509,
    ffi::PE_MsCounterSign,
    ffi::PE_MsCounterSign_it_certificates
);

declare_iterator!(
    MsCounterSigners,
    SignerInfo<'a>,
    ffi::PE_SignerInfo,
    ffi::PE_MsCounterSign,
    ffi::PE_MsCounterSign_it_signers
);

/// Interface over the structure described by the OID `1.3.6.1.4.1.311.10.3.28` (szOID_PLATFORM_MANIFEST_BINARY_ID)
///
/// The internal structure is not documented but we can infer the following structure:
///
/// ```text
/// szOID_PLATFORM_MANIFEST_BINARY_ID ::= SET OF BinaryID
/// ```
///
/// `BinaryID` being an alias of UTF8STRING
pub struct MsManifestBinaryID<'a> {
    ptr: cxx::UniquePtr<ffi::PE_MsManifestBinaryID>,
    _owner: PhantomData<&'a ffi::PE_SignerInfo>,
}

impl std::fmt::Debug for MsManifestBinaryID<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsManifestBinaryID")
            .field("manifest_id", &self.manifest_id())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_MsManifestBinaryID> for MsManifestBinaryID<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_MsManifestBinaryID>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl MsManifestBinaryID<'_> {
    pub fn manifest_id(&self) -> String {
        self.ptr.manifest_id().to_string()
    }
}
