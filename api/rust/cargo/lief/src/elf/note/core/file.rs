use lief_ffi as ffi;
use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::declare_fwd_iterator;
use crate::elf::note::NoteBase;

/// An entry in the core file mapping
pub struct Entry<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_CoreFile_entry>,
    _owner: PhantomData<&'a ffi::ELF_CoreFile>,
}

impl Entry<'_> {
    /// Start address of the mapping
    pub fn start(&self) -> u64 {
        self.ptr.start()
    }

    /// End address of the mapping
    pub fn end(&self) -> u64 {
        self.ptr.end()
    }

    /// Offset in the file
    pub fn file_ofs(&self) -> u64 {
        self.ptr.file_ofs()
    }

    /// File path
    pub fn path(&self) -> String {
        self.ptr.path().to_string()
    }
}

impl std::fmt::Debug for Entry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("start", &format_args!("0x{:x}", self.start()))
            .field("end", &format_args!("0x{:x}", self.end()))
            .field("file_ofs", &format_args!("0x{:x}", self.file_ofs()))
            .field("path", &self.path())
            .finish()
    }
}

impl<'a> FromFFI<ffi::ELF_CoreFile_entry> for Entry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_CoreFile_entry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Note representing core mapped files (`NT_FILE`)
pub struct File<'a> {
    ptr: cxx::UniquePtr<ffi::ELF_CoreFile>,
    _owner: PhantomData<&'a ffi::ELF_Binary>,
}

impl File<'_> {
    /// Number of file entries
    pub fn count(&self) -> u64 {
        self.ptr.count()
    }

    /// Return the list of file entries as an iterator
    pub fn files(&self) -> Entries<'_> {
        Entries::new(self.ptr.files())
    }
}

impl NoteBase for File<'_> {
    fn get_base(&self) -> &ffi::ELF_Note {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl FromFFI<ffi::ELF_CoreFile> for File<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_CoreFile>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for File<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn NoteBase;
        f.debug_struct("CoreFile")
            .field("base", &base)
            .field("count", &self.count())
            .finish()
    }
}

declare_fwd_iterator!(
    Entries,
    Entry<'a>,
    ffi::ELF_CoreFile_entry,
    ffi::ELF_CoreFile,
    ffi::ELF_CoreFile_it_files
);
