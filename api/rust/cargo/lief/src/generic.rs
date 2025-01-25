use lief_ffi as ffi;
use bitflags::bitflags;
use crate::{to_slice, declare_fwd_iterator};
use crate::common::{into_optional, FromFFI};
use crate::assembly::Instructions;

use std::pin::Pin;

/// Trait shared by all the symbols in executable formats
pub trait Symbol {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::AbstractSymbol;

    /// Symbol's name
    fn name(&self) -> String {
        self.as_generic().name().to_string()
    }
    /// Symbol's value whose interpretation depends on the symbol's kind.
    /// Usually this is the address of the symbol though.
    fn value(&self) -> u64 {
        self.as_generic().value()
    }
    /// Size of the symbol (can be 0)
    fn size(&self) -> u64 {
        self.as_generic().size()
    }
}

impl std::fmt::Debug for &dyn Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Symbol")
            .field("name", &self.name())
            .field("value", &self.value())
            .field("size", &self.size())
            .finish()
    }
}

/// Trait shared by all the sections in executable formats
pub trait Section {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::AbstractSection;

    /// Name of the section
    fn name(&self) -> String {
        self.as_generic().name().to_string()
    }

    /// Size of the section **in the file**
    fn size(&self) -> u64 {
        self.as_generic().size()
    }

    /// Offset of the section **in the file**
    fn offset(&self) -> u64 {
        self.as_generic().offset()
    }

    /// Address of the section **in memory**
    fn virtual_address(&self) -> u64 {
        self.as_generic().virtual_address()
    }

    /// Content of the section
    fn content(&self) -> &[u8] {
        to_slice!(self.as_generic().content());
    }
}

impl std::fmt::Debug for &dyn Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Section")
            .field("name", &self.name())
            .field("size", &self.size())
            .field("offset", &self.offset())
            .field("virtual_address", &self.virtual_address())
            .finish()
    }
}

pub trait Relocation {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::AbstractRelocation;

    /// Address where the relocation should take place
    fn address(&self) -> u64 {
        self.as_generic().address()
    }

    /// Size of the relocation
    fn size(&self) -> u64 {
        self.as_generic().size()
    }
}

impl std::fmt::Debug for &dyn Relocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relocation")
            .field("address", &self.address())
            .field("size", &self.size())
            .finish()
    }
}

pub trait Binary {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::AbstractBinary;

    #[doc(hidden)]
    fn as_pin_mut_generic(&mut self) -> Pin<&mut ffi::AbstractBinary>;

    /// Binary's entrypoint
    fn entrypoint(&self) -> u64 {
        self.as_generic().entrypoint()
    }

    /// Default base address where the binary should be mapped
    fn imagebase(&self) -> u64 {
        self.as_generic().imagebase()
    }

    /// Whether the current binary is **an executable** and **position independent**
    fn is_pie(&self) -> bool {
        self.as_generic().is_pie()
    }

    /// Whether the binary defines a non-executable stack
    fn has_nx(&self) -> bool {
        self.as_generic().has_nx()
    }

    /// Original file size of the binary
    fn original_size(&self) -> u64 {
        self.as_generic().original_size()
    }

    /// Return the debug info if present. It can be either a
    /// [`crate::pdb::DebugInfo`] or [`crate::dwarf::DebugInfo`].
    ///
    /// For ELF and Mach-O binaries, it returns the given DebugInfo object **only**
    /// if the binary embeds the DWARF debug info in the binary itself.
    ///
    /// For PE file, this function tries to find the **external** PDB using
    /// the [`crate::pe::debug::CodeViewPDB::filename`] output (if present). One can also
    /// use [`crate::pdb::load`] or [`crate::pdb::DebugInfo::from`] to get PDB debug
    /// info.
    ///
    /// <div class="warning">
    /// This function requires LIEF's extended version otherwise it always return `None`
    /// </div>
    fn debug_info(&self) -> Option<crate::DebugInfo> {
        into_optional(self.as_generic().debug_info())
    }

    /// Disassemble code starting a the given virtual address and with the given
    /// size.
    ///
    /// ```
    /// let insts = binary.disassemble(0xacde, 100);
    /// for inst in insts {
    ///     println!("{}", inst.to_string());
    /// }
    /// ```
    ///
    /// See also [`crate::assembly::Instruction`] and [`crate::assembly::Instructions`]
    fn disassemble(&self, address: u64, size: u64) -> InstructionsIt {
        InstructionsIt::new(self.as_generic().disassemble(address, size))
    }

    /// Disassemble code for the given symbol name
    ///
    /// ```
    /// let insts = binary.disassemble_symbol("__libc_start_main");
    /// for inst in insts {
    ///     println!("{}", inst.to_string());
    /// }
    /// ```
    ///
    /// See also [`crate::assembly::Instruction`] and [`crate::assembly::Instructions`]
    fn disassemble_symbol(&self, name: &str) -> InstructionsIt {
        InstructionsIt::new(self.as_generic().disassemble_function(name.to_string()))
    }

    /// Disassemble code at the given virtual address
    ///
    /// ```
    /// let insts = binary.disassemble_address(0xacde);
    /// for inst in insts {
    ///     println!("{}", inst.to_string());
    /// }
    /// ```
    ///
    /// See also [`crate::assembly::Instruction`] and [`crate::assembly::Instructions`]
    fn disassemble_address(&self, address: u64) -> InstructionsIt {
        InstructionsIt::new(self.as_generic().disassemble_address(address))
    }

    /// Disassemble code provided by the given slice at the specified `address` parameter.
    ///
    /// See also [`crate::assembly::Instruction`] and [`crate::assembly::Instructions`]
    fn disassemble_slice(&self, slice: &[u8], address: u64) -> InstructionsIt {
        unsafe {
            InstructionsIt::new(self.as_generic().disassemble_buffer(
                    slice.as_ptr(), slice.len().try_into().unwrap(),
                    address))
        }
    }

    /// Assemble **and patch** the provided assembly code at the specified address.
    ///
    /// The generated assembly is returned by the function
    ///
    /// ```
    /// let mut bin = get_binary();
    ///
    /// let Vec<u8> bytes = bin.assemble(0x12000440, r#"
    /// xor rax, rbx;
    /// mov rcx, rax;
    /// "#);
    /// ```
    fn assemble(&mut self, address: u64, asm: &str) -> Vec<u8> {
        Vec::from(self.as_pin_mut_generic().assemble(address, asm).as_slice())
    }
}

pub trait DebugInfo {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::AbstracDebugInfo;
}


bitflags! {
    /// Flags used to characterize the semantics of the function
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FunctionFlags: u32 {
        const NONE = 0x0;
        /// The function acts as constructor.
        ///
        /// Usually this flag is associated with functions
        /// that are located in the `.init_array`, `__mod_init_func` or `.tls` sections
        const CONSTRUCTOR = 0x1;

        /// The function acts as a destructor.
        ///
        /// Usually this flag is associated with functions
        /// that are located in the `.fini_array` or `__mod_term_func` sections
        const DESTRUCTOR = 0x2;

        /// The function is associated with Debug information
        const DEBUG_INFO = 0x4;

        /// The function is exported by the binary and the [`Function::address`]
        /// returns its virtual address in the binary
        const EXPORTED = 0x8;

        /// The function is **imported** by the binary and the [`Function::address`]
        /// should return 0
        const IMPORTED = 0x10;
    }
}


impl From<u32> for FunctionFlags {
    fn from(value: u32) -> Self {
        FunctionFlags::from_bits_truncate(value)
    }
}

impl From<FunctionFlags> for u32 {
    fn from(value: FunctionFlags) -> Self {
        value.bits()
    }
}

impl std::fmt::Display for FunctionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

/// Structure that represents a binary's function
pub struct Function {
    ptr: cxx::UniquePtr<ffi::AbstractFunction>,
}

impl FromFFI<ffi::AbstractFunction> for Function {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::AbstractFunction>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Symbol for Function {
    fn as_generic(&self) -> &lief_ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Function {
    /// Flags characterizing the semantics of the function
    pub fn flags(&self) -> FunctionFlags {
        FunctionFlags::from(self.ptr.flags())
    }

    /// Address of the function (if not imported)
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }
}

impl std::fmt::Debug for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Function")
            .field("name", &self.name())
            .field("address", &self.address())
            .field("flags", &self.flags())
            .finish()
    }
}

declare_fwd_iterator!(
    Functions,
    Function,
    ffi::AbstractFunction,
    ffi::AbstractBinary,
    ffi::AbstractBinary_it_functions
);

declare_fwd_iterator!(
    InstructionsIt,
    Instructions,
    ffi::asm_Instruction,
    ffi::AbstractBinary,
    ffi::AbstractBinary_it_instructions
);
