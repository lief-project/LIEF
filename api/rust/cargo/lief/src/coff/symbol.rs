use lief_ffi as ffi;

use std::marker::PhantomData;
use std::pin::Pin;

use crate::to_slice;
use crate::common::{into_optional, FromFFI};
use crate::{generic, declare_iterator};

use super::Section;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum StorageClass {
    INVALID,
    END_OF_FUNCTION,
    NONE,
    AUTOMATIC,
    EXTERNAL,
    STATIC,
    REGISTER,
    EXTERNAL_DEF,
    LABEL,
    UNDEFINED_LABEL,
    MEMBER_OF_STRUCT,
    ARGUMENT,
    STRUCT_TAG,
    MEMBER_OF_UNION,
    UNION_TAG,
    TYPE_DEFINITION,
    UNDEFINED_STATIC,
    ENUM_TAG,
    MEMBER_OF_ENUM,
    REGISTER_PARAM,
    BIT_FIELD,
    BLOCK,
    FUNCTION,
    END_OF_STRUCT,
    FILE,
    SECTION,
    WEAK_EXTERNAL,
    CLR_TOKEN,
    UNKNOWN(u32),
}

impl From<u32> for StorageClass {
    fn from(value: u32) -> Self {
        match value {
            0x000000ff => StorageClass::INVALID,
            0xffffffff => StorageClass::END_OF_FUNCTION,
            0x00000000 => StorageClass::NONE,
            0x00000001 => StorageClass::AUTOMATIC,
            0x00000002 => StorageClass::EXTERNAL,
            0x00000003 => StorageClass::STATIC,
            0x00000004 => StorageClass::REGISTER,
            0x00000005 => StorageClass::EXTERNAL_DEF,
            0x00000006 => StorageClass::LABEL,
            0x00000007 => StorageClass::UNDEFINED_LABEL,
            0x00000008 => StorageClass::MEMBER_OF_STRUCT,
            0x00000009 => StorageClass::ARGUMENT,
            0x0000000a => StorageClass::STRUCT_TAG,
            0x0000000b => StorageClass::MEMBER_OF_UNION,
            0x0000000c => StorageClass::UNION_TAG,
            0x0000000d => StorageClass::TYPE_DEFINITION,
            0x0000000e => StorageClass::UNDEFINED_STATIC,
            0x0000000f => StorageClass::ENUM_TAG,
            0x00000010 => StorageClass::MEMBER_OF_ENUM,
            0x00000011 => StorageClass::REGISTER_PARAM,
            0x00000012 => StorageClass::BIT_FIELD,
            0x00000064 => StorageClass::BLOCK,
            0x00000065 => StorageClass::FUNCTION,
            0x00000066 => StorageClass::END_OF_STRUCT,
            0x00000067 => StorageClass::FILE,
            0x00000068 => StorageClass::SECTION,
            0x00000069 => StorageClass::WEAK_EXTERNAL,
            0x0000006b => StorageClass::CLR_TOKEN,
            _ => StorageClass::UNKNOWN(value),

        }
    }
}
impl From<StorageClass> for u32 {
    fn from(value: StorageClass) -> u32 {
        match value {
            StorageClass::INVALID => 0x000000ff,
            StorageClass::END_OF_FUNCTION => 0xffffffff,
            StorageClass::NONE => 0x00000000,
            StorageClass::AUTOMATIC => 0x00000001,
            StorageClass::EXTERNAL => 0x00000002,
            StorageClass::STATIC => 0x00000003,
            StorageClass::REGISTER => 0x00000004,
            StorageClass::EXTERNAL_DEF => 0x00000005,
            StorageClass::LABEL => 0x00000006,
            StorageClass::UNDEFINED_LABEL => 0x00000007,
            StorageClass::MEMBER_OF_STRUCT => 0x00000008,
            StorageClass::ARGUMENT => 0x00000009,
            StorageClass::STRUCT_TAG => 0x0000000a,
            StorageClass::MEMBER_OF_UNION => 0x0000000b,
            StorageClass::UNION_TAG => 0x0000000c,
            StorageClass::TYPE_DEFINITION => 0x0000000d,
            StorageClass::UNDEFINED_STATIC => 0x0000000e,
            StorageClass::ENUM_TAG => 0x0000000f,
            StorageClass::MEMBER_OF_ENUM => 0x00000010,
            StorageClass::REGISTER_PARAM => 0x00000011,
            StorageClass::BIT_FIELD => 0x00000012,
            StorageClass::BLOCK => 0x00000064,
            StorageClass::FUNCTION => 0x00000065,
            StorageClass::END_OF_STRUCT => 0x00000066,
            StorageClass::FILE => 0x00000067,
            StorageClass::SECTION => 0x00000068,
            StorageClass::WEAK_EXTERNAL => 0x00000069,
            StorageClass::CLR_TOKEN => 0x0000006b,
            StorageClass::UNKNOWN(value) => value,
        }
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum BaseType {
    TY_NULL,
    TY_VOID,
    TY_CHAR,
    TY_SHORT,
    TY_INT,
    TY_LONG,
    TY_FLOAT,
    TY_DOUBLE,
    TY_STRUCT,
    TY_UNION,
    TY_ENUM,
    TY_MOE,
    TY_BYTE,
    TY_WORD,
    TY_UINT,
    TY_DWORD,
    UNKNOWN(u32),
}

impl From<u32> for BaseType {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => BaseType::TY_NULL,
            0x00000001 => BaseType::TY_VOID,
            0x00000002 => BaseType::TY_CHAR,
            0x00000003 => BaseType::TY_SHORT,
            0x00000004 => BaseType::TY_INT,
            0x00000005 => BaseType::TY_LONG,
            0x00000006 => BaseType::TY_FLOAT,
            0x00000007 => BaseType::TY_DOUBLE,
            0x00000008 => BaseType::TY_STRUCT,
            0x00000009 => BaseType::TY_UNION,
            0x0000000a => BaseType::TY_ENUM,
            0x0000000b => BaseType::TY_MOE,
            0x0000000c => BaseType::TY_BYTE,
            0x0000000d => BaseType::TY_WORD,
            0x0000000e => BaseType::TY_UINT,
            0x0000000f => BaseType::TY_DWORD,
            _ => BaseType::UNKNOWN(value),

        }
    }
}
impl From<BaseType> for u32 {
    fn from(value: BaseType) -> u32 {
        match value {
            BaseType::TY_NULL => 0x00000000,
            BaseType::TY_VOID => 0x00000001,
            BaseType::TY_CHAR => 0x00000002,
            BaseType::TY_SHORT => 0x00000003,
            BaseType::TY_INT => 0x00000004,
            BaseType::TY_LONG => 0x00000005,
            BaseType::TY_FLOAT => 0x00000006,
            BaseType::TY_DOUBLE => 0x00000007,
            BaseType::TY_STRUCT => 0x00000008,
            BaseType::TY_UNION => 0x00000009,
            BaseType::TY_ENUM => 0x0000000a,
            BaseType::TY_MOE => 0x0000000b,
            BaseType::TY_BYTE => 0x0000000c,
            BaseType::TY_WORD => 0x0000000d,
            BaseType::TY_UINT => 0x0000000e,
            BaseType::TY_DWORD => 0x0000000f,
            BaseType::UNKNOWN(value) => value,

        }
    }
}



#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ComplexType {
    TY_NULL,
    TY_POINTER,
    TY_FUNCTION,
    TY_ARRAY,
    UNKNOWN(u32),
}

impl From<u32> for ComplexType {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => ComplexType::TY_NULL,
            0x00000001 => ComplexType::TY_POINTER,
            0x00000002 => ComplexType::TY_FUNCTION,
            0x00000003 => ComplexType::TY_ARRAY,
            _ => ComplexType::UNKNOWN(value),

        }
    }
}
impl From<ComplexType> for u32 {
    fn from(value: ComplexType) -> u32 {
        match value {
            ComplexType::TY_NULL => 0x00000000,
            ComplexType::TY_POINTER => 0x00000001,
            ComplexType::TY_FUNCTION => 0x00000002,
            ComplexType::TY_ARRAY => 0x00000003,
            ComplexType::UNKNOWN(value) => value,

        }
    }
}

/// Structure that represents a COFF symbol.
///
/// **Warning:** The [`crate::generic::Symbol::value`] should be interpreted in perspective of
/// the [`Symbol::storage_class`].
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table>
pub struct Symbol<'a> {
    pub(crate) ptr: cxx::UniquePtr<ffi::COFF_Symbol>,
    _owner: PhantomData<&'a ()>
}

impl FromFFI<ffi::COFF_Symbol> for Symbol<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_Symbol>) -> Self {
        Self {
            ptr,
            _owner: PhantomData
        }
    }
}

impl std::fmt::Debug for Symbol<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("Symbol")
            .field("base", &base)
            .field("storage_class", &self.storage_class())
            .field("base_type", &self.base_type())
            .field("complex_type", &self.complex_type())
            .field("section_idx", &self.section_idx())
            .finish()
    }
}


impl std::fmt::Display for Symbol<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

impl Symbol<'_> {
    /// Auxiliary symbols associated with this symbol.
    pub fn auxiliary_symbols(&self) -> ItAuxiliarySymbols<'_> {
        ItAuxiliarySymbols::new(self.ptr.auxiliary_symbols())
    }

    /// Storage class of the symbol which indicates what kind of definition a
    /// symbol represents.
    pub fn storage_class(&self) -> StorageClass {
        StorageClass::from(self.ptr.storage_class())
    }

    /// The simple (base) data type
    pub fn base_type(&self) -> BaseType {
        BaseType::from(self.ptr.base_type())
    }

    /// The complex type (if any)
    pub fn complex_type(&self) -> ComplexType {
        ComplexType::from(self.ptr.complex_type())
    }

    /// The signed integer that identifies the section, using a one-based index
    /// into the section table. Some values have special meaning:
    ///
    /// * 0: The symbol record is not yet assigned a section. A value of zero
    ///   indicates that a reference to an external symbol is defined elsewhere.
    ///   A value of non-zero is a common symbol with a size that is specified
    ///   by the value.
    /// * -1: The symbol has an absolute (non-relocatable) value and is not an
    ///   address.
    /// * -2: The symbol provides general type or debugging information but does
    ///   not correspond to a section. Microsoft tools use this setting along
    ///   with `.file` records
    pub fn section_idx(&self) -> i16 {
        self.ptr.section_idx()
    }

    /// Section associated with this symbol (if any)
    pub fn section(&self) -> Option<Section<'_>> {
        into_optional(self.ptr.section())
    }

    pub fn is_external(&self) -> bool {
        self.ptr.is_external()
    }

    pub fn is_weak_external(&self) -> bool {
        self.ptr.is_weak_external()
    }

    pub fn is_undefined(&self) -> bool {
        self.ptr.is_undefined()
    }

    pub fn is_function_line_info(&self) -> bool {
        self.ptr.is_function_line_info()
    }

    pub fn is_absolute(&self) -> bool {
        self.ptr.is_absolute()
    }

    pub fn is_file_record(&self) -> bool {
        self.ptr.is_file_record()
    }

    pub fn is_function(&self) -> bool {
        self.ptr.is_function()
    }

    /// Demangled representation of the symbol or an empty string if it can't be demangled
    pub fn demangled_name(&self) -> String {
        self.ptr.demangled_name().to_string()
    }
}

impl generic::Symbol for Symbol<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_pin_mut_generic(&mut self) -> Pin<&mut ffi::AbstractSymbol> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::AbstractSymbol
                    as *mut ffi::AbstractSymbol)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

/// Class that represents an auxiliary symbols.
///
/// An auxiliary symbol has the same size as a regular [`Symbol`] (18 bytes) but its content
/// depends on the the parent symbol.
#[derive(Debug)]
pub enum AuxiliarySymbols<'a> {
    /// Auxiliary Format 1 from the PE-COFF documentation
    FunctionDefinition(AuxiliaryFunctionDefinition<'a>),
    /// Auxiliary Format 2: .bf and .ef Symbols from the PE-COFF documentation
    BfAndEf(AuxiliaryBfAndEf<'a>),
    /// Auxiliary Format 3: Weak Externals from the PE-COFF documentation
    WeakExternal(AuxiliaryWeakExternal<'a>),
    /// Auxiliary Format 4: Files from the PE-COFF documentation
    File(AuxiliaryFile<'a>),
    /// Auxiliary Format 5: Section Definitions from the PE-COFF documentation
    SectionDefinition(AuxiliarySectionDefinition<'a>),
    CLRToken(AuxiliaryCLRToken<'a>),
    Unknown(AuxiliarySymbol<'a>),
}


impl FromFFI<ffi::COFF_AuxiliarySymbol> for AuxiliarySymbols<'_> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::COFF_AuxiliarySymbol>) -> Self {
        unsafe {
            let aux_ref = ffi_entry.as_ref().unwrap();
            if ffi::COFF_AuxiliaryFile::classof(aux_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::COFF_AuxiliarySymbol>;
                    type To = cxx::UniquePtr<ffi::COFF_AuxiliaryFile>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                AuxiliarySymbols::File(AuxiliaryFile::from_ffi(raw))
            } else if ffi::COFF_AuxiliarybfAndefSymbol::classof(aux_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::COFF_AuxiliarySymbol>;
                    type To = cxx::UniquePtr<ffi::COFF_AuxiliarybfAndefSymbol>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                AuxiliarySymbols::BfAndEf(AuxiliaryBfAndEf::from_ffi(raw))
            } else if ffi::COFF_AuxiliaryCLRToken::classof(aux_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::COFF_AuxiliarySymbol>;
                    type To = cxx::UniquePtr<ffi::COFF_AuxiliaryCLRToken>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                AuxiliarySymbols::CLRToken(AuxiliaryCLRToken::from_ffi(raw))
            } else if ffi::COFF_AuxiliaryFunctionDefinition::classof(aux_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::COFF_AuxiliarySymbol>;
                    type To = cxx::UniquePtr<ffi::COFF_AuxiliaryFunctionDefinition>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                AuxiliarySymbols::FunctionDefinition(AuxiliaryFunctionDefinition::from_ffi(raw))
            } else if ffi::COFF_AuxiliaryWeakExternal::classof(aux_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::COFF_AuxiliarySymbol>;
                    type To = cxx::UniquePtr<ffi::COFF_AuxiliaryWeakExternal>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                AuxiliarySymbols::WeakExternal(AuxiliaryWeakExternal::from_ffi(raw))
            } else if ffi::COFF_AuxiliarySectionDefinition::classof(aux_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::COFF_AuxiliarySymbol>;
                    type To = cxx::UniquePtr<ffi::COFF_AuxiliarySectionDefinition>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                AuxiliarySymbols::SectionDefinition(AuxiliarySectionDefinition::from_ffi(raw))
            } else {
                AuxiliarySymbols::Unknown(AuxiliarySymbol::from_ffi(ffi_entry))
            }
        }
    }
}

/// This auxiliary symbol represents a filename (auxiliary format 4)
///
/// The [`crate::generic::Symbol::name`] itself should start with `.file`, and this auxiliary record
/// gives the name of a source-code file.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-4-files>
pub struct AuxiliaryFile<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_AuxiliaryFile>,
    _owner: PhantomData<&'a ffi::COFF_Symbol>,
}

impl std::fmt::Debug for AuxiliaryFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxiliaryFile")
            .field("filename", &self.filename())
            .finish()
    }
}

impl FromFFI<ffi::COFF_AuxiliaryFile> for AuxiliaryFile<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_AuxiliaryFile>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AuxiliaryFile<'_> {
    /// The associated filename
    pub fn filename(&self) -> String {
        self.ptr.filename().to_string()
    }
}

pub struct AuxiliaryBfAndEf<'a> {
    #[allow(dead_code)]
    ptr: cxx::UniquePtr<ffi::COFF_AuxiliarybfAndefSymbol>,
    _owner: PhantomData<&'a ffi::COFF_Symbol>,
}

impl std::fmt::Debug for AuxiliaryBfAndEf<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxiliaryBfAndEf")
            .finish()
    }
}

impl FromFFI<ffi::COFF_AuxiliarybfAndefSymbol> for AuxiliaryBfAndEf<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_AuxiliarybfAndefSymbol>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub struct AuxiliaryCLRToken<'a> {
    #[allow(dead_code)]
    ptr: cxx::UniquePtr<ffi::COFF_AuxiliaryCLRToken>,
    _owner: PhantomData<&'a ffi::COFF_Symbol>,
}

impl AuxiliaryCLRToken<'_> {
    /// `IMAGE_AUX_SYMBOL_TYPE` which should be `IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF` (1)
    pub fn aux_type(&self) -> u8 {
        self.ptr.aux_type()
    }

    /// Reserved value (should be 0)
    pub fn reserved(&self) -> u8 {
        self.ptr.reserved()
    }

    /// Index in the symbol table
    pub fn symbol_idx(&self) -> u32 {
        self.ptr.symbol_idx()
    }

    /// Symbol referenced by [`AuxiliaryCLRToken::symbol_idx`] (if resolved)
    pub fn symbol(&self) -> Option<Symbol<'_>> {
        into_optional(self.ptr.symbol())
    }

    /// Reserved (padding) values. Should be 0
    pub fn rgb_reserved(&self) -> &[u8] {
        to_slice!(self.ptr.rgb_reserved());
    }
}


impl std::fmt::Debug for AuxiliaryCLRToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxiliaryCLRToken")
            .field("aux_type", &self.aux_type())
            .field("reserved", &self.reserved())
            .field("symbol_idx", &self.symbol_idx())
            .finish()
    }
}

impl FromFFI<ffi::COFF_AuxiliaryCLRToken> for AuxiliaryCLRToken<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_AuxiliaryCLRToken>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// This auxiliary symbols marks the beginning of a function definition.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-1-function-definitions>
pub struct AuxiliaryFunctionDefinition<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_AuxiliaryFunctionDefinition>,
    _owner: PhantomData<&'a ffi::COFF_Symbol>,
}

impl FromFFI<ffi::COFF_AuxiliaryFunctionDefinition> for AuxiliaryFunctionDefinition<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_AuxiliaryFunctionDefinition>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for AuxiliaryFunctionDefinition<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxiliaryFunctionDefinition")
            .field("tag_index", &self.tag_index())
            .field("total_size", &self.total_size())
            .field("ptr_to_line_number", &self.ptr_to_line_number())
            .field("ptr_to_next_func", &self.ptr_to_next_func())
            .field("padding", &self.padding())
            .finish()
    }
}

impl AuxiliaryFunctionDefinition<'_> {
    /// The symbol-table index of the corresponding `.bf` (begin function)
    /// symbol record.
    pub fn tag_index(&self) -> u32 {
        self.ptr.tag_index()
    }

    /// The size of the executable code for the function itself.
    ///
    /// If the function is in its own section, the `SizeOfRawData` in the section
    /// header is greater or equal to this field, depending on alignment considerations.
    pub fn total_size(&self) -> u32 {
        self.ptr.total_size()
    }

    /// The file offset of the first COFF line-number entry for the function,
    /// or zero if none exists (deprecated)
    pub fn ptr_to_line_number(&self) -> u32 {
        self.ptr.ptr_to_line_number()
    }

    /// The symbol-table index of the record for the next function. If the function
    /// is the last in the symbol table, this field is set to zero.
    pub fn ptr_to_next_func(&self) -> u32 {
        self.ptr.ptr_to_next_func()
    }

    /// Padding value (should be 0)
    pub fn padding(&self) -> u16 {
        self.ptr.padding()
    }

}

/// This auxiliary symbol exposes information about the associated section.
///
/// It **duplicates** some information that are provided in the section header
pub struct AuxiliarySectionDefinition<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_AuxiliarySectionDefinition>,
    _owner: PhantomData<&'a ffi::COFF_Symbol>,
}

impl FromFFI<ffi::COFF_AuxiliarySectionDefinition> for AuxiliarySectionDefinition<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_AuxiliarySectionDefinition>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for AuxiliarySectionDefinition<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxiliarySectionDefinition")
            .field("length", &self.length())
            .field("nb_relocs", &self.nb_relocs())
            .field("nb_line_numbers", &self.nb_line_numbers())
            .field("checksum", &self.checksum())
            .field("section_idx", &self.section_idx())
            .field("selection", &self.selection())
            .finish()
    }
}

impl AuxiliarySectionDefinition<'_> {
    /// The size of section data. The same as `SizeOfRawData` in the section header.
    pub fn length(&self) -> u32 {
        self.ptr.length()
    }

    /// The number of relocation entries for the section.
    pub fn nb_relocs(&self) -> u16 {
        self.ptr.nb_relocs()
    }

    /// The number of line-number entries for the section.
    pub fn nb_line_numbers(&self) -> u16 {
        self.ptr.nb_line_numbers()
    }

    /// The checksum for communal data. It is applicable if the `IMAGE_SCN_LNK_COMDAT` flag is set
    /// in the section header.
    pub fn checksum(&self) -> u32 {
        self.ptr.checksum()
    }

    /// One-based index into the section table for the associated section.
    /// This is used when the COMDAT selection setting is 5.
    pub fn section_idx(&self) -> u32 {
        self.ptr.section_idx()
    }

    /// The COMDAT selection number. This is applicable if the section is a
    /// COMDAT section.
    pub fn selection(&self) -> ComdatSelection {
        ComdatSelection::from(self.ptr.selection())
    }

    /// Reserved value (should be 0)
    pub fn reserved(&self) -> u8 {
        self.ptr.reserved()
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ComdatSelection {
    NONE,
    NODUPLICATES,
    ANY,
    SAME_SIZE,
    EXACT_MATCH,
    ASSOCIATIVE,
    LARGEST,
    UNKNOWN(u8),
}

impl From<u8> for ComdatSelection {
    fn from(value: u8) -> Self {
        match value {
            0x00000000 => ComdatSelection::NONE,
            0x00000001 => ComdatSelection::NODUPLICATES,
            0x00000002 => ComdatSelection::ANY,
            0x00000003 => ComdatSelection::SAME_SIZE,
            0x00000004 => ComdatSelection::EXACT_MATCH,
            0x00000005 => ComdatSelection::ASSOCIATIVE,
            0x00000006 => ComdatSelection::LARGEST,
            _ => ComdatSelection::UNKNOWN(value),

        }
    }
}
impl From<ComdatSelection> for u8 {
    fn from(value: ComdatSelection) -> u8 {
        match value {
            ComdatSelection::NONE => 0x00000000,
            ComdatSelection::NODUPLICATES => 0x00000001,
            ComdatSelection::ANY => 0x00000002,
            ComdatSelection::SAME_SIZE => 0x00000003,
            ComdatSelection::EXACT_MATCH => 0x00000004,
            ComdatSelection::ASSOCIATIVE => 0x00000005,
            ComdatSelection::LARGEST => 0x00000006,
            ComdatSelection::UNKNOWN(value) => value,

        }
    }
}


/// "Weak externals" are a mechanism for object files that allows flexibility at
/// link time. A module can contain an unresolved external symbol (`sym1`), but
/// it can also include an auxiliary record that indicates that if `sym1` is not
/// present at link time, another external symbol (`sym2`) is used to resolve
/// references instead.
///
/// If a definition of `sym1` is linked, then an external reference to the
/// symbol is resolved normally. If a definition of `sym1` is not linked, then all
/// references to the weak external for `sym1` refer to `sym2` instead. The external
/// symbol, `sym2`, must always be linked; typically, it is defined in the module
/// that contains the weak reference to `sym1`.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-3-weak-externals>
pub struct AuxiliaryWeakExternal<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_AuxiliaryWeakExternal>,
    _owner: PhantomData<&'a ffi::COFF_Symbol>,
}


#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Characteristics {
    SEARCH_NOLIBRARY,
    SEARCH_LIBRARY,
    SEARCH_ALIAS,
    ANTI_DEPENDENCY,
    UNKNOWN(u32),
}

impl From<u32> for Characteristics {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Characteristics::SEARCH_NOLIBRARY,
            0x00000002 => Characteristics::SEARCH_LIBRARY,
            0x00000003 => Characteristics::SEARCH_ALIAS,
            0x00000004 => Characteristics::ANTI_DEPENDENCY,
            _ => Characteristics::UNKNOWN(value),

        }
    }
}
impl From<Characteristics> for u32 {
    fn from(value: Characteristics) -> u32 {
        match value {
            Characteristics::SEARCH_NOLIBRARY => 0x00000001,
            Characteristics::SEARCH_LIBRARY => 0x00000002,
            Characteristics::SEARCH_ALIAS => 0x00000003,
            Characteristics::ANTI_DEPENDENCY => 0x00000004,
            Characteristics::UNKNOWN(value) => value,

        }
    }
}

impl FromFFI<ffi::COFF_AuxiliaryWeakExternal> for AuxiliaryWeakExternal<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_AuxiliaryWeakExternal>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for AuxiliaryWeakExternal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxiliaryWeakExternal")
            .field("sym_idx", &self.sym_idx())
            .field("characteristics", &self.characteristics())
            .finish()
    }
}

impl AuxiliaryWeakExternal<'_> {
    /// The symbol-table index of `sym2`, the symbol to be linked if `sym1` is not
    /// found.
    pub fn sym_idx(&self) -> u32 {
        self.ptr.sym_idx()
    }

    pub fn characteristics(&self) -> Characteristics{
        Characteristics::from(self.ptr.characteristics())
    }

    pub fn padding(&self) -> &[u8] {
        to_slice!(self.ptr.padding());
    }
}


pub struct AuxiliarySymbol<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_AuxiliarySymbol>,
    _owner: PhantomData<&'a ffi::COFF_Symbol>,
}

impl FromFFI<ffi::COFF_AuxiliarySymbol> for AuxiliarySymbol<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_AuxiliarySymbol>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl std::fmt::Debug for AuxiliarySymbol<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxiliarySymbol")
            .finish()
    }
}

impl AuxiliarySymbol<'_> {
    /// Return the raw representation of this symbol
    pub fn payload(&self) -> &[u8] {
        to_slice!(self.ptr.payload());
    }
}

declare_iterator!(
    ItAuxiliarySymbols,
    AuxiliarySymbols<'a>,
    ffi::COFF_AuxiliarySymbol,
    ffi::COFF_Symbol,
    ffi::COFF_Symbol_it_auxiliary_symbols
);
