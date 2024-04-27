use lief_ffi as ffi;
use std::fmt;
use crate::common::FromFFI;
use std::marker::PhantomData;

pub struct Sysv<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_SysvHash>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}

impl Sysv<'_> {
    pub fn nbucket(&self) -> u32 {
        self.ptr.nbucket()
    }
    pub fn nchain(&self) -> u32 {
        self.ptr.nchain()
    }
    pub fn buckets(&self) -> Vec<u32> {
        Vec::from(self.ptr.buckets().as_slice())
    }
    pub fn chains(&self) -> Vec<u32> {
        Vec::from(self.ptr.chains().as_slice())
    }
}

impl fmt::Debug for Sysv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sysv")
            .field("nbucket", &self.nbucket())
            .field("nchain", &self.nchain())
            .field("buckets", &self.buckets())
            .field("chains", &self.chains())
            .finish()
    }
}

impl FromFFI<ffi::ELF_SysvHash> for Sysv<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_SysvHash>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

pub struct Gnu<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_GnuHash>,
    _owner: PhantomData<&'a ffi::ELF_Binary>
}


impl Gnu<'_> {
    pub fn nb_buckets(&self) -> u32 {
        self.ptr.nb_buckets()
    }
    pub fn symbol_index(&self) -> u32 {
        self.ptr.symbol_index()
    }
    pub fn shift2(&self) -> u32 {
        self.ptr.shift2()
    }
    pub fn maskwords(&self) -> u32 {
        self.ptr.maskwords()
    }
    pub fn bloom_filters(&self) -> Vec<u64> {
        Vec::from(self.ptr.bloom_filters().as_slice())
    }
    pub fn buckets(&self) -> Vec<u32> {
        Vec::from(self.ptr.buckets().as_slice())
    }
    pub fn hash_values(&self) -> Vec<u32> {
        Vec::from(self.ptr.hash_values().as_slice())
    }
}

impl fmt::Debug for Gnu<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GnuHash")
            .field("nb_buckets", &self.nb_buckets())
            .field("symbol_index", &self.symbol_index())
            .field("shift2", &self.shift2())
            .field("maskwords", &self.maskwords())
            .field("bloom_filters", &self.bloom_filters())
            .field("buckets", &self.buckets())
            .field("hash_values", &self.hash_values())
            .finish()
    }
}

impl FromFFI<ffi::ELF_GnuHash> for Gnu<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_GnuHash>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}



