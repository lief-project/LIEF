use lief_ffi as ffi;
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

declare_fwd_iterator!(
    InstructionsIt,
    Instructions,
    ffi::asm_Instruction,
    ffi::AbstractBinary,
    ffi::AbstractBinary_it_instructions
);
