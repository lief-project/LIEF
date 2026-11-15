use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::dwarf::editor::types::EditorType;
use crate::enum_from_int;

/// This structure represents a struct-like type which can be:
///
/// - `DW_TAG_class_type`
/// - `DW_TAG_structure_type`
/// - `DW_TAG_union_type`
pub struct Struct {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_StructType>,
}

impl FromFFI<ffi::DWARF_editor_StructType> for Struct {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_StructType>) -> Self {
        Self { ptr: cmd }
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    Kind: u32 {
        CLASS = 0x00000000,
        STRUCT = 0x00000001,
        UNION = 0x00000002,
    }
}

impl Struct {
    /// Define the overall size which is equivalent to the `sizeof` of the current
    /// type.
    ///
    /// This function defines the `DW_AT_byte_size` attribute
    pub fn set_size(&mut self, size: u64) {
        self.ptr.pin_mut().set_size(size);
    }

    /// Add a member to the current struct-like
    pub fn add_member(&mut self, name: &str, ty: &mut dyn EditorType) -> Member {
        cxx::let_cxx_string!(__cxx_name = name);
        Member::from_ffi(self.ptr.pin_mut().add_member(&__cxx_name, ty.get_base()))
    }

    /// Add a member to the current struct-like at the specified offset
    pub fn add_member_at_offset(
        &mut self,
        name: &str,
        ty: &mut dyn EditorType,
        offset: u64,
    ) -> Member {
        cxx::let_cxx_string!(__cxx_name = name);
        Member::from_ffi(self.ptr.pin_mut().add_member_with_offset(
            &__cxx_name,
            ty.get_base(),
            offset,
        ))
    }

    /// Add a bitfield to the current struct-like
    pub fn add_bitfield(&mut self, name: &str, ty: &mut dyn EditorType, bitsize: u64) -> Member {
        cxx::let_cxx_string!(__cxx_name = name);
        Member::from_ffi(
            self.ptr
                .pin_mut()
                .add_bitfield(&__cxx_name, ty.get_base(), bitsize),
        )
    }

    /// Add a bitfield to the current struct-like at the specified offset
    pub fn add_bitfield_at_offset(
        &mut self,
        name: &str,
        ty: &mut dyn EditorType,
        bitsize: u64,
        bitoffset: u64,
    ) -> Member {
        cxx::let_cxx_string!(__cxx_name = name);
        Member::from_ffi(self.ptr.pin_mut().add_bitfield_with_offset(
            &__cxx_name,
            ty.get_base(),
            bitsize,
            bitoffset,
        ))
    }
}

impl EditorType for Struct {
    fn get_base(&self) -> &ffi::DWARF_editor_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

#[allow(dead_code)]
pub struct Member {
    ptr: cxx::UniquePtr<ffi::DWARF_editor_StructType_Member>,
}

impl FromFFI<ffi::DWARF_editor_StructType_Member> for Member {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_editor_StructType_Member>) -> Self {
        Self { ptr: cmd }
    }
}
