use std::marker::PhantomData;

use super::attributes::Attribute;
use super::X509;
use crate::pe::Algorithms;
use crate::to_slice;
use crate::common::{FromFFI, into_optional};
use crate::declare_iterator;
use lief_ffi as ffi;

/// SignerInfo as described in the [RFC 2315](https://tools.ietf.org/html/rfc2315#section-9.2)
pub struct SignerInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_SignerInfo>,
    _owner: PhantomData<&'a ()>, // Can be own by Signature or PKCS9CounterSignature
}

impl std::fmt::Debug for SignerInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerInfo")
            .field("version", &self.version())
            .field("issuer", &self.issuer())
            .field("digest_algorithm", &self.digest_algorithm())
            .field("encryption_algorithm", &self.encryption_algorithm())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_SignerInfo> for SignerInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_SignerInfo>) -> Self {
        SignerInfo {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> SignerInfo<'a> {
    /// Should be 1
    pub fn version(&self) -> u32 {
        self.ptr.version()
    }

    /// Return the [`X509::issuer`] used by this signer
    pub fn issuer(&self) -> String {
        self.ptr.issuer().to_string()
    }

    /// Algorithm used to hash the file.
    pub fn digest_algorithm(&self) -> Algorithms {
        Algorithms::from(self.ptr.digest_algorithm())
    }

    /// Return the (public-key) algorithm used to encrypt the signature
    pub fn encryption_algorithm(&self) -> Algorithms {
        Algorithms::from(self.ptr.encryption_algorithm())
    }

    /// Return the serial number associated with the x509 certificate
    /// used by this signer.
    pub fn serial_number(&self) -> &[u8] {
        to_slice!(self.ptr.serial_number());
    }

    /// Return the signature created by the signing certificate's private key
    pub fn encrypted_digest(&self) -> Vec<u8> {
        Vec::from(self.ptr.encrypted_digest().as_slice())
    }

    /// [`X509`] certificate used by this signer.
    pub fn cert(&self) -> Option<X509> {
        into_optional(self.ptr.cert())
    }

    /// Iterator over the **authenticated** [`Attribute`]
    pub fn authenticated_attributes(&self) -> AuthenticatedAttributes {
        AuthenticatedAttributes::new(self.ptr.authenticated_attributes())
    }

    /// Iterator over the **unauthenticated** [`Attribute`]
    pub fn unauthenticated_attributes(&self) -> UnAuthenticatedAttributes {
        UnAuthenticatedAttributes::new(self.ptr.unauthenticated_attributes())
    }

    /// Raw blob that is signed by the signer certificate
    pub fn raw_auth_data(&self) -> &[u8] {
        to_slice!(self.ptr.raw_auth_data());
    }
}

declare_iterator!(
    Signers,
    SignerInfo<'a>,
    ffi::PE_SignerInfo,
    ffi::PE_Signature,
    ffi::PE_Signature_it_signers
);
declare_iterator!(
    AuthenticatedAttributes,
    Attribute<'a>,
    ffi::PE_Attribute,
    ffi::PE_SignerInfo,
    ffi::PE_SignerInfo_it_authenticated_attributes
);
declare_iterator!(
    UnAuthenticatedAttributes,
    Attribute<'a>,
    ffi::PE_Attribute,
    ffi::PE_SignerInfo,
    ffi::PE_SignerInfo_it_unauthenticated_attributes
);
