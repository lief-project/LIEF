use lief_ffi as ffi;
use std::path::Path;
use crate::common::FromFFI;
use crate::declare_fwd_iterator;
use crate::common::into_optional;
use crate::declare_iterator;
use crate::assembly::Instructions;
use super::{Relocation, Symbol, Section, Header, String};

pub struct Binary {
    ptr: cxx::UniquePtr<ffi::COFF_Binary>,
}

impl FromFFI<ffi::COFF_Binary> for Binary {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_Binary>) -> Self {
        Self { ptr }
    }
}

impl Binary {
    /// Parse from a file path given as a string
    pub fn parse<P: AsRef<Path>>(path: P) -> Option<Self> {
        let ffi = ffi::COFF_Binary::parse(path.as_ref().to_str().unwrap());
        if ffi.is_null() {
            return None;
        }
        Some(Binary::from_ffi(ffi))
    }

    /// The COFF header
    pub fn header(&self) -> Header<'_> {
        Header::from_ffi(self.ptr.header())
    }

    /// Iterator over the different sections located in this COFF binary
    pub fn sections(&self) -> Sections<'_> {
        Sections::new(self.ptr.sections())
    }

    /// Iterator over **all** the relocations used by this COFF binary
    pub fn relocations(&self) -> Relocations<'_> {
        Relocations::new(self.ptr.relocations())
    }

    /// Iterator over the COFF's symbols
    pub fn symbols(&self) -> Symbols<'_> {
        Symbols::new(self.ptr.symbols())
    }

    /// Iterator over the functions implemented in this COFF
    pub fn functions(&self) -> Functions<'_> {
        Functions::new(self.ptr.functions())
    }

    /// Iterator over the COFF's strings
    pub fn string_table(&self) -> Strings<'_> {
        Strings::new(self.ptr.string_table())
    }

    /// Try to find the COFF string at the given offset in the COFF string table.
    ///
    /// <div class="warning">
    /// This offset must include the first 4 bytes holding the size of the table. Hence,
    /// the first string starts a the offset 4.
    /// </div>
    pub fn find_string(&self, offset: u32) -> Option<String<'_>> {
        into_optional(self.ptr.find_string(offset))
    }

    /// Try to find the function (symbol) with the given name
    pub fn find_function(&self, name: &str) -> Option<Symbol<'_>> {
        into_optional(self.ptr.find_function(name))
    }

    /// Try to find the function (symbol) with the given **demangled** name
    pub fn find_demangled_function(&self, name: &str) -> Option<Symbol<'_>> {
        into_optional(self.ptr.find_demangled_function(name))
    }

    /// Disassemble code provided by the given slice at the specified `address` parameter.
    ///
    /// See also [`crate::assembly::Instruction`] and [`crate::assembly::Instructions`]
    pub fn disassemble_slice(&self, slice: &[u8], address: u64) -> InstructionsIt<'_> {
        unsafe {
            InstructionsIt::new(self.ptr.disassemble_buffer(
                    slice.as_ptr(), slice.len().try_into().unwrap(),
                    address))
        }
    }

    /// Disassemble code for the given function name
    ///
    /// ```
    /// let insts = binary.disassemble_function("int __cdecl bar(int, int)");
    /// for inst in insts {
    ///     println!("{}", inst.to_string());
    /// }
    /// ```
    ///
    /// See also [`crate::assembly::Instruction`] and [`crate::assembly::Instructions`]
    pub fn disassemble_function(&self, name: &str) -> InstructionsIt<'_> {
        InstructionsIt::new(self.ptr.disassemble_function(name.to_string()))
    }


    /// Disassemble code for the given symbol
    ///
    /// ```
    /// let symbol = binary.find_demangled_function("int __cdecl bar(int, int)").unwrap();
    /// let insts = binary.disassemble_symbol(&symbol);
    /// for inst in insts {
    ///     println!("{}", inst.to_string());
    /// }
    /// ```
    ///
    /// See also [`crate::assembly::Instruction`] and [`crate::assembly::Instructions`]
    pub fn disassemble_symbol(&self, symbol: &Symbol) -> InstructionsIt<'_> {
        InstructionsIt::new(self.ptr.disassemble_symbol(symbol.ptr.as_ref().unwrap()))
    }
}

impl std::fmt::Display for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

impl std::fmt::Debug for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("COFF Binary")
            .finish()
    }
}



declare_iterator!(
    Relocations,
    Relocation<'a>,
    ffi::COFF_Relocation,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_relocations
);

declare_iterator!(
    Sections,
    Section<'a>,
    ffi::COFF_Section,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_sections
);

declare_iterator!(
    Symbols,
    Symbol<'a>,
    ffi::COFF_Symbol,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_symbols
);

declare_iterator!(
    Strings,
    String<'a>,
    ffi::COFF_String,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_strings
);

declare_iterator!(
    Functions,
    Symbol<'a>,
    ffi::COFF_Symbol,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_functions
);


declare_fwd_iterator!(
    InstructionsIt,
    Instructions,
    ffi::asm_Instruction,
    ffi::COFF_Binary,
    ffi::COFF_Binary_it_instructions
);
