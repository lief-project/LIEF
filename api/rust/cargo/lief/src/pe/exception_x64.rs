//! Module related to the x86_64 exception unwinding support

use lief_ffi as ffi;

use std::marker::PhantomData;

use crate::{declare_fwd_iterator, to_opt, to_slice};
use crate::common::{into_optional, FromFFI};
use super::exception::ExceptionInfo;
use bitflags::bitflags;

/// This structure represents an entry in the exception table (`.pdata` section)
/// for the x86-64 architecture.
///
/// Reference: <https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64>
pub struct RuntimeFunction<'a> {
    ptr: cxx::UniquePtr<ffi::PE_RuntimeFunctionX64>,
    _owner: PhantomData<&'a ffi::PE_Binary>
}

impl FromFFI<ffi::PE_RuntimeFunctionX64> for RuntimeFunction<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_RuntimeFunctionX64>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl std::fmt::Debug for RuntimeFunction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn ExceptionInfo;
        f.debug_struct("RuntimeFunction(x86_64)")
            .field("rva_start", &base.rva_start())
            .field("rva_end", &self.rva_end())
            .field("unwind_rva", &self.unwind_rva())
            .field("size", &self.size())
            .field("unwind_info", &self.unwind_info())
            .finish()
    }
}

impl ExceptionInfo for RuntimeFunction<'_> {
    fn as_generic(&self) -> &ffi::PE_ExceptionInfo {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl RuntimeFunction<'_> {
    /// Function end address
    pub fn rva_end(&self) -> u32 {
        self.ptr.rva_end()
    }

    /// Unwind info address
    pub fn unwind_rva(&self) -> u32 {
        self.ptr.unwind_rva()
    }

    /// Size of the function (in bytes)
    pub fn size(&self) -> u32 {
        self.ptr.size()
    }

    /// Detailed unwind information
    pub fn unwind_info(&self) -> Option<UnwindInfo> {
        into_optional(self.ptr.unwind_info())
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum UnwindOpcodes {
    /// Push a nonvolatile integer register, decrementing RSP by 8.
    /// The operation info is the number of the register. Because of the
    /// constraints on epilogs, `PUSH_NONVOL` unwind codes must appear first
    /// in the prolog and correspondingly, last in the unwind code array.
    /// This relative ordering applies to all other unwind codes except
    /// [`UnwindOpcodes::PUSH_MACHFRAME`].
    PUSH_NONVOL,

    /// Allocate a large-sized area on the stack.
    /// There are two forms. If the operation info equals 0,
    /// then the size of the allocation divided by 8 is recorded in the next slot,
    /// allowing an allocation up to 512K - 8. If the operation info equals 1,
    /// then the unscaled size of the allocation is recorded in the next two
    /// slots in little-endian format, allowing allocations up to 4GB - 8.
    ALLOC_LARGE,

    /// Allocate a small-sized area on the stack. The size of the allocation is
    /// the operation info field * 8 + 8, allowing allocations from 8 to 128 bytes.
    ALLOC_SMALL,

    /// Establish the frame pointer register by setting the register to some
    /// offset of the current RSP. The offset is equal to the Frame Register
    /// offset (scaled) field in the UNWIND_INFO * 16, allowing offsets from
    /// 0 to 240. The use of an offset permits establishing a frame pointer that
    /// points to the middle of the fixed stack allocation, helping code density
    /// by allowing more accesses to use short instruction forms. The operation
    /// info field is reserved and shouldn't be us
    SET_FPREG,

    /// Save a nonvolatile integer register on the stack using a MOV instead of a
    /// PUSH. This code is primarily used for shrink-wrapping, where a nonvolatile
    /// register is saved to the stack in a position that was previously allocated.
    /// The operation info is the number of the register. The scaled-by-8 stack
    /// offset is recorded in the next unwind operation code slot, as described
    /// in the note above
    SAVE_NONVOL,

    /// Save a nonvolatile integer register on the stack with a long offset,
    /// using a MOV instead of a PUSH. This code is primarily used for
    /// shrink-wrapping, where a nonvolatile register is saved to the stack in a
    /// position that was previously allocated. The operation info is the number
    /// of the register. The unscaled stack offset is recorded in the next two
    /// unwind operation code slots, as described in the note above.
    SAVE_NONVOL_FAR,

    /// This entry is only revelant for version 2. It describes the function
    /// epilog.
    EPILOG,

    /// Reserved
    /// Originally SAVE_XMM128_FAR in version 1, but deprecated and removed
    SPARE,

    /// Save all 128 bits of a nonvolatile XMM register on the stack.
    /// The operation info is the number of the register. The scaled-by-16 stack
    /// offset is recorded in the next slot.
    SAVE_XMM128,

    /// Save all 128 bits of a nonvolatile XMM register on the stack with a
    /// long offset. The operation info is the number of the register.
    /// The unscaled stack offset is recorded in the next two slots.
    SAVE_XMM128_FAR,

    /// Push a machine frame. This unwind code is used to record the effect of a
    /// hardware interrupt or exception.
    PUSH_MACHFRAME,

    UNKNOWN(u32),
}

impl From<u32> for UnwindOpcodes {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => UnwindOpcodes::PUSH_NONVOL,
            0x00000001 => UnwindOpcodes::ALLOC_LARGE,
            0x00000002 => UnwindOpcodes::ALLOC_SMALL,
            0x00000003 => UnwindOpcodes::SET_FPREG,
            0x00000004 => UnwindOpcodes::SAVE_NONVOL,
            0x00000005 => UnwindOpcodes::SAVE_NONVOL_FAR,
            0x00000006 => UnwindOpcodes::EPILOG,
            0x00000007 => UnwindOpcodes::SPARE,
            0x00000008 => UnwindOpcodes::SAVE_XMM128,
            0x00000009 => UnwindOpcodes::SAVE_XMM128_FAR,
            0x0000000a => UnwindOpcodes::PUSH_MACHFRAME,
            _ => UnwindOpcodes::UNKNOWN(value),

        }
    }
}
impl From<UnwindOpcodes> for u32 {
    fn from(value: UnwindOpcodes) -> u32 {
        match value {
            UnwindOpcodes::PUSH_NONVOL => 0x00000000,
            UnwindOpcodes::ALLOC_LARGE => 0x00000001,
            UnwindOpcodes::ALLOC_SMALL => 0x00000002,
            UnwindOpcodes::SET_FPREG => 0x00000003,
            UnwindOpcodes::SAVE_NONVOL => 0x00000004,
            UnwindOpcodes::SAVE_NONVOL_FAR => 0x00000005,
            UnwindOpcodes::EPILOG => 0x00000006,
            UnwindOpcodes::SPARE => 0x00000007,
            UnwindOpcodes::SAVE_XMM128 => 0x00000008,
            UnwindOpcodes::SAVE_XMM128_FAR => 0x00000009,
            UnwindOpcodes::PUSH_MACHFRAME => 0x0000000a,
            UnwindOpcodes::UNKNOWN(value) => value,

        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum UnwindReg {
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
    UNKNOWN(u32),
}

impl From<u32> for UnwindReg {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => UnwindReg::RAX,
            0x00000001 => UnwindReg::RCX,
            0x00000002 => UnwindReg::RDX,
            0x00000003 => UnwindReg::RBX,
            0x00000004 => UnwindReg::RSP,
            0x00000005 => UnwindReg::RBP,
            0x00000006 => UnwindReg::RSI,
            0x00000007 => UnwindReg::RDI,
            0x00000008 => UnwindReg::R8,
            0x00000009 => UnwindReg::R9,
            0x0000000a => UnwindReg::R10,
            0x0000000b => UnwindReg::R11,
            0x0000000c => UnwindReg::R12,
            0x0000000d => UnwindReg::R13,
            0x0000000e => UnwindReg::R14,
            0x0000000f => UnwindReg::R15,
            _ => UnwindReg::UNKNOWN(value),

        }
    }
}
impl From<UnwindReg> for u32 {
    fn from(value: UnwindReg) -> u32 {
        match value {
            UnwindReg::RAX => 0x00000000,
            UnwindReg::RCX => 0x00000001,
            UnwindReg::RDX => 0x00000002,
            UnwindReg::RBX => 0x00000003,
            UnwindReg::RSP => 0x00000004,
            UnwindReg::RBP => 0x00000005,
            UnwindReg::RSI => 0x00000006,
            UnwindReg::RDI => 0x00000007,
            UnwindReg::R8 => 0x00000008,
            UnwindReg::R9 => 0x00000009,
            UnwindReg::R10 => 0x0000000a,
            UnwindReg::R11 => 0x0000000b,
            UnwindReg::R12 => 0x0000000c,
            UnwindReg::R13 => 0x0000000d,
            UnwindReg::R14 => 0x0000000e,
            UnwindReg::R15 => 0x0000000f,
            UnwindReg::UNKNOWN(value) => value,

        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct UnwindFlags: u8 {
        /// The function has an exception handler that should be called when looking
        /// for functions that need to examine exceptions.
        const EXCEPTION_HANDLER = 0x1;

        /// The function has a termination handler that should be called when
        /// unwinding an exception.
        const TERMINATE_HANDLER = 0x2;

        /// The chained info payload references a previous `RUNTIME_FUNCTION`
        const CHAIN_INFO = 0x4;
    }
}


impl From<u8> for UnwindFlags {
    fn from(value: u8) -> Self {
        UnwindFlags::from_bits_truncate(value)
    }
}

impl From<UnwindFlags> for u8 {
    fn from(value: UnwindFlags) -> Self {
        value.bits()
    }
}

impl std::fmt::Display for UnwindFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

/// This structure represents the `UNWIND_INFO` which records the effects
/// a function has on the stack pointer, and where the nonvolatile registers
/// are saved on the stack.
pub struct UnwindInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_RuntimeFunctionX64_unwind_info_t>,
    _owner: PhantomData<&'a ffi::PE_Binary>
}

impl FromFFI<ffi::PE_RuntimeFunctionX64_unwind_info_t> for UnwindInfo<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_RuntimeFunctionX64_unwind_info_t>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl UnwindInfo<'_> {
    /// Version number of the unwind data, currently 1 or 2.
    pub fn version(&self) -> u8 {
        self.ptr.version()
    }

    /// See: [`UnwindFlags`]
    pub fn flags(&self) -> UnwindFlags {
        UnwindFlags::from(self.ptr.flags())
    }

    /// Length of the function prolog in bytes.
    pub fn sizeof_prologue(&self) -> u8 {
        self.ptr.sizeof_prologue()
    }

    /// The number of slots in the unwind codes array. Some unwind codes, for
    /// example, [`UnwindOpcodes::SAVE_NONVOL`], require more than one slot in the
    /// array
    pub fn count_opcodes(&self) -> u8 {
        self.ptr.count_opcodes()
    }

    /// If nonzero, then the function uses a frame pointer (FP), and this field
    /// is the number of the nonvolatile register used as the frame pointer,
    /// using the same encoding for the operation info field of [`UnwindOpcodes`]
    /// nodes.
    pub fn frame_reg(&self) -> u8 {
        self.ptr.frame_reg()
    }

    /// If the frame register field is nonzero, this field is the scaled offset
    /// from RSP that is applied to the FP register when it's established
    pub fn frame_reg_offset(&self) -> u8 {
        self.ptr.frame_reg_offset()
    }

    /// An array of items that explains the effect of the prolog on the
    /// nonvolatile registers and RSP
    pub fn raw_opcodes(&self) -> &[u8] {
        to_slice!(self.ptr.raw_opcodes());
    }

    /// Iterator over the unwind code which outputs [`Opcodes`]
    pub fn opcodes(&self) -> OpcodesIterator {
        OpcodesIterator::new(self.ptr.opcodes())
    }

    /// An image-relative pointer to either the function's language-specific
    /// exception or termination handler. This value is set if one of these
    /// flags is set: [`UnwindFlags::EXCEPTION_HANDLER`],
    /// [`UnwindFlags::TERMINATE_HANDLER`]
    pub fn handler(&self) -> Option<u32> {
        to_opt!(&ffi::PE_RuntimeFunctionX64_unwind_info_t::handler, &self);
    }

    /// If [`UnwindFlags::CHAIN_INFO`] is set, this attributes references the
    /// chained runtime function.
    pub fn chained(&self) -> Option<RuntimeFunction> {
        into_optional(self.ptr.chained())
    }
}

impl std::fmt::Debug for UnwindInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnwindInfo")
            .field("version", &self.version())
            .field("flags", &self.flags())
            .field("sizeof_prologue", &self.sizeof_prologue())
            .field("count_opcodes", &self.count_opcodes())
            .field("frame_reg", &self.frame_reg())
            .field("frame_reg_offset", &self.frame_reg_offset())
            .field("handler", &self.handler())
            .finish()
    }
}


impl std::fmt::Display for UnwindInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}


/// Trait shared by all [`Opcodes`]
pub trait Opcode {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::PE_unwind_x64_Code;

    /// Offset in the prolog
    fn position(&self) -> u32 {
        self.as_generic().position()
    }

    /// The original opcode
    fn opcode(&self) -> UnwindOpcodes {
        UnwindOpcodes::from(self.as_generic().opcode())
    }
}


impl std::fmt::Display for &dyn Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_generic().to_string())
    }
}

/// The different `x86_64` unwind opcodes.
pub enum Opcodes<'a> {
    /// Represents a stack-allocation operation
    Alloc(Alloc<'a>),

    /// Push a nonvolatile integer register
    PushNonVol(PushNonVol<'a>),

    /// Push a machine frame
    PushMachFrame(PushMachFrame<'a>),

    /// Establish the frame pointer register
    SetFPReg(SetFPReg<'a>),

    /// Save a nonvolatile integer register
    SaveNonVolatile(SaveNonVolatile<'a>),

    SaveXMM128 (SaveXMM128 <'a>),

    /// Describes the function's epilog
    Epilog(Epilog<'a>),
    Spare(Spare<'a>),
}

impl<'a> FromFFI<ffi::PE_unwind_x64_Code> for Opcodes<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_unwind_x64_Code>) -> Self {
        unsafe {
            let code_ref = ffi_entry.as_ref().unwrap();
            if ffi::PE_unwind_x64_Alloc::classof(code_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_unwind_x64_Code>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_x64_Alloc>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Opcodes::Alloc(Alloc::from_ffi(raw))
            } else if ffi::PE_unwind_x64_PushNonVol::classof(code_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_unwind_x64_Code>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_x64_PushNonVol>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Opcodes::PushNonVol(PushNonVol::from_ffi(raw))
            } else if ffi::PE_unwind_x64_PushMachFrame::classof(code_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_unwind_x64_Code>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_x64_PushMachFrame>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Opcodes::PushMachFrame(PushMachFrame::from_ffi(raw))
            } else if ffi::PE_unwind_x64_SetFPReg::classof(code_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_unwind_x64_Code>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_x64_SetFPReg>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Opcodes::SetFPReg(SetFPReg::from_ffi(raw))
            } else if ffi::PE_unwind_x64_SaveNonVolatile::classof(code_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_unwind_x64_Code>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_x64_SaveNonVolatile>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Opcodes::SaveNonVolatile(SaveNonVolatile::from_ffi(raw))
            } else if ffi::PE_unwind_x64_SaveXMM128::classof(code_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_unwind_x64_Code>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_x64_SaveXMM128>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Opcodes::SaveXMM128(SaveXMM128::from_ffi(raw))
            } else if ffi::PE_unwind_x64_Epilog::classof(code_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_unwind_x64_Code>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_x64_Epilog>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Opcodes::Epilog(Epilog::from_ffi(raw))
            } else if ffi::PE_unwind_x64_Spare::classof(code_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_unwind_x64_Code>;
                    type To = cxx::UniquePtr<ffi::PE_unwind_x64_Spare>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Opcodes::Spare(Spare::from_ffi(raw))
            } else {
                panic!("Unknown opcode");
            }
        }
    }
}


/// This structure represents a stack-allocation operation
/// ([`UnwindOpcodes::ALLOC_SMALL`] or [`UnwindOpcodes::ALLOC_LARGE`]).
pub struct Alloc<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_x64_Alloc>,
    _owner: PhantomData<&'a ffi::PE_RuntimeFunctionX64_unwind_info_t>
}

impl FromFFI<ffi::PE_unwind_x64_Alloc> for Alloc<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_x64_Alloc>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl Opcode for Alloc<'_> {
    fn as_generic(&self) -> &ffi::PE_unwind_x64_Code {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Alloc<'_> {
    /// The size allocated
    pub fn size(&self) -> u32 {
        self.ptr.size()
    }
}

/// Push a nonvolatile integer register, decrementing RSP by 8
pub struct PushNonVol<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_x64_PushNonVol>,
    _owner: PhantomData<&'a ffi::PE_RuntimeFunctionX64_unwind_info_t>
}

impl FromFFI<ffi::PE_unwind_x64_PushNonVol> for PushNonVol<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_x64_PushNonVol>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl Opcode for PushNonVol<'_> {
    fn as_generic(&self) -> &ffi::PE_unwind_x64_Code {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl PushNonVol<'_> {
    /// The register pushed
    pub fn reg(&self) -> UnwindReg {
        UnwindReg::from(self.ptr.reg())
    }
}

/// Push a machine frame
pub struct PushMachFrame<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_x64_PushMachFrame>,
    _owner: PhantomData<&'a ffi::PE_RuntimeFunctionX64_unwind_info_t>
}

impl FromFFI<ffi::PE_unwind_x64_PushMachFrame> for PushMachFrame<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_x64_PushMachFrame>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl Opcode for PushMachFrame<'_> {
    fn as_generic(&self) -> &ffi::PE_unwind_x64_Code {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl PushMachFrame<'_> {
    /// The register pushed
    pub fn value(&self) -> u8 {
        self.ptr.value()
    }
}

/// Establish the frame pointer register by setting the register to some offset
/// of the current RSP
pub struct SetFPReg<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_x64_SetFPReg>,
    _owner: PhantomData<&'a ffi::PE_RuntimeFunctionX64_unwind_info_t>
}

impl FromFFI<ffi::PE_unwind_x64_SetFPReg> for SetFPReg<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_x64_SetFPReg>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl Opcode for SetFPReg<'_> {
    fn as_generic(&self) -> &ffi::PE_unwind_x64_Code {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl SetFPReg<'_> {
    /// The register pushed
    pub fn reg(&self) -> UnwindReg {
        UnwindReg::from(self.ptr.reg())
    }
}

/// Save a nonvolatile integer register on the stack using a `MOV` instead of a
/// `PUSH`.
pub struct SaveNonVolatile<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_x64_SaveNonVolatile>,
    _owner: PhantomData<&'a ffi::PE_RuntimeFunctionX64_unwind_info_t>
}

impl FromFFI<ffi::PE_unwind_x64_SaveNonVolatile> for SaveNonVolatile<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_x64_SaveNonVolatile>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl Opcode for SaveNonVolatile<'_> {
    fn as_generic(&self) -> &ffi::PE_unwind_x64_Code {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl SaveNonVolatile<'_> {
    pub fn reg(&self) -> UnwindReg {
        UnwindReg::from(self.ptr.reg())
    }

    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }
}

pub struct SaveXMM128<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_x64_SaveXMM128>,
    _owner: PhantomData<&'a ffi::PE_RuntimeFunctionX64_unwind_info_t>
}

impl FromFFI<ffi::PE_unwind_x64_SaveXMM128> for SaveXMM128<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_x64_SaveXMM128>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl Opcode for SaveXMM128<'_> {
    fn as_generic(&self) -> &ffi::PE_unwind_x64_Code {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl SaveXMM128<'_> {
    pub fn num(&self) -> u8 {
        self.ptr.num()
    }

    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }
}

/// Describes the function's epilog
pub struct Epilog<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_x64_Epilog>,
    _owner: PhantomData<&'a ffi::PE_RuntimeFunctionX64_unwind_info_t>
}

impl FromFFI<ffi::PE_unwind_x64_Epilog> for Epilog<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_x64_Epilog>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl Opcode for Epilog<'_> {
    fn as_generic(&self) -> &ffi::PE_unwind_x64_Code {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Epilog<'_> {
    pub fn flags(&self) -> u8 {
        self.ptr.flags()
    }

    pub fn size(&self) -> u32 {
        self.ptr.size()
    }
}

pub struct Spare<'a> {
    ptr: cxx::UniquePtr<ffi::PE_unwind_x64_Spare>,
    _owner: PhantomData<&'a ffi::PE_RuntimeFunctionX64_unwind_info_t>
}

impl FromFFI<ffi::PE_unwind_x64_Spare> for Spare<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_unwind_x64_Spare>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl Opcode for Spare<'_> {
    fn as_generic(&self) -> &ffi::PE_unwind_x64_Code {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

declare_fwd_iterator!(
    OpcodesIterator,
    Opcodes<'a>,
    ffi::PE_unwind_x64_Code,
    ffi::PE_RuntimeFunctionX64_unwind_info_t,
    ffi::PE_RuntimeFunctionX64_unwind_info_t_it_opcodes
);

