use lief_ffi as ffi;
use num_bigint::BigUint;

use crate::common::FromFFI;
use std::marker::PhantomData;

/// Structure that wraps an RSA key
pub struct RsaInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_RsaInfo>,
    _owner: PhantomData<&'a ()>,
}

impl std::fmt::Debug for RsaInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaInfo")
            .field("key_size", &self.key_size())
            .field("has_public_key", &self.has_public_key())
            .field("has_private_key", &self.has_private_key())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_RsaInfo> for RsaInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_RsaInfo>) -> Self {
        RsaInfo {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> RsaInfo<'a> {
    #[allow(non_snake_case)]
    /// RSA public modulus
    pub fn N(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.N().as_slice())
    }

    /// RSA public exponent
    #[allow(non_snake_case)]
    pub fn E(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.E().as_slice())
    }

    #[allow(non_snake_case)]
    /// RSA private exponent
    pub fn D(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.D().as_slice())
    }

    #[allow(non_snake_case)]
    /// First prime factor
    pub fn P(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.P().as_slice())
    }
    #[allow(non_snake_case)]
    /// Second prime factor
    pub fn Q(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.Q().as_slice())
    }

    /// Size of the public modulus (in bits)
    pub fn key_size(&self) -> u32 {
        self.ptr.key_size()
    }

    /// True if it embeds a public key
    pub fn has_public_key(&self) -> bool {
        self.ptr.has_public_key()
    }

    /// True if it embeds a private key
    pub fn has_private_key(&self) -> bool {
        self.ptr.has_private_key()
    }
}
