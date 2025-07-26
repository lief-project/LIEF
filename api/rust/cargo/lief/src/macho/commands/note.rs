use super::Command;
use crate::to_slice;
use crate::common::FromFFI;
use lief_ffi as ffi;
use std::marker::PhantomData;

/// Class that represent the `LC_NOTE` command.
///
/// This command is used to include arbitrary notes or metadata within a binary.
pub struct Note<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_NoteCommand>,
    _owner: PhantomData<&'a ffi::MachO_Binary>,
}

impl Note<'_> {
    /// Offset of the data associated with this note
    pub fn note_offset(&self) -> u64 {
        self.ptr.note_offset()
    }

    /// Size of the data referenced by the note_offset
    pub fn note_size(&self) -> u64 {
        self.ptr.note_size()
    }

    /// Owner of the note (e.g. `AIR_METALLIB`)
    pub fn owner(&self) -> &[u8] {
        to_slice!(self.ptr.owner());
    }

    pub fn set_note_offset(&mut self, offset: u64) {
        self.ptr.pin_mut().set_note_offset(offset);
    }

    pub fn set_note_size(&mut self, size: u64) {
        self.ptr.pin_mut().set_note_size(size);
    }
}

impl std::fmt::Debug for Note<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn Command;
        f.debug_struct("Note")
            .field("base", &base)
            .field("note_offset", &self.note_offset())
            .field("note_size", &self.note_size())
            .field("owner", &self.owner())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_NoteCommand> for Note<'a> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::MachO_NoteCommand>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Command for Note<'_> {
    fn get_base(&self) -> &ffi::MachO_Command {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
