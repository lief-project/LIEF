import lief
import pytest
from utils import get_sample
from textwrap import dedent

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_lief():
    pdb = lief.pdb.load(get_sample("private/PDB/LIEF.pdb"))

    assert pdb.find_type(400) is not None
    assert pdb.find_type(400000000) is None

    types = list(pdb.types)
    assert len(types) == 116669

    ty_modifier: lief.pdb.types.Modifier = types[0]
    assert isinstance(ty_modifier, lief.pdb.types.Modifier)
    assert ty_modifier.kind == lief.pdb.Type.KIND.MODIFIER

    underlying: lief.pdb.types.Simple = ty_modifier.underlying_type
    assert isinstance(underlying, lief.pdb.types.Simple)
    assert underlying.kind == lief.pdb.Type.KIND.SIMPLE
    assert ty_modifier.to_decl() == "const char"
    assert ty_modifier.size == 1
    assert ty_modifier.name == "char"

    ty_pointer: lief.pdb.types.Pointer = types[7]
    assert isinstance(ty_pointer, lief.pdb.types.Pointer)
    assert ty_pointer.kind == lief.pdb.Type.KIND.POINTER
    assert ty_pointer.to_decl() == "const class std::basic_string<char,std::char_traits<char>,std::allocator<char> > *"
    assert ty_pointer.name == "std::basic_string<char,std::char_traits<char>,std::allocator<char> > *"
    assert ty_pointer.size == 8

    underlying: lief.pdb.types.Modifier = ty_pointer.underlying_type
    assert isinstance(underlying, lief.pdb.types.Modifier)
    assert underlying.kind == lief.pdb.Type.KIND.MODIFIER

    ty_function: lief.pdb.types.Function = types[10]
    assert isinstance(ty_function, lief.pdb.types.Function)
    assert ty_function.kind == lief.pdb.Type.KIND.FUNCTION

    assert ty_function.to_decl() == "class std::basic_string<char,std::char_traits<char>,std::allocator<char> > (const class std::basic_string<char,std::char_traits<char>,std::allocator<char> > *)"
    assert ty_function.name is None
    assert ty_function.size is None

    ty_enum: lief.pdb.types.Enum = types[11]
    assert isinstance(ty_enum, lief.pdb.types.Enum)
    assert ty_enum.kind == lief.pdb.Type.KIND.ENUM

    assert ty_enum.to_decl() == dedent("""\
    enum std::float_denorm_style {
        denorm_indeterminate = -1,
        denorm_absent = 0,
        denorm_present = 1
    }""")
    assert ty_enum.name == "std::float_denorm_style"
    assert ty_enum.size == 4
    assert ty_enum.unique_name == ".?AW4float_denorm_style@std@@"
    assert ty_enum.underlying_type.name == "int32_t"

    ty_struct: lief.pdb.types.Structure = types[19]
    assert isinstance(ty_struct, lief.pdb.types.Structure)
    assert ty_struct.kind == lief.pdb.Type.KIND.STRUCTURE

    assert ty_struct.to_decl() == "struct std::_String_constructor_concat_tag"
    assert ty_struct.name == "std::_String_constructor_concat_tag"
    assert ty_struct.size == 0
    assert ty_struct.unique_name == ".?AU_String_constructor_concat_tag@std@@"

    ty_array: lief.pdb.types.Array = types[154]
    assert isinstance(ty_array, lief.pdb.types.Array)
    assert ty_array.kind == lief.pdb.Type.KIND.ARRAY

    assert ty_array.to_decl() == "char[23]"
    assert ty_array.name is None
    assert ty_array.size == 23
    assert ty_array.index_type.name == "unsigned long long"
    assert ty_array.element_type.name == "char"

    ty_bf: lief.pdb.types.BitField = types[3925]
    assert isinstance(ty_bf, lief.pdb.types.BitField)
    assert ty_bf.kind == lief.pdb.Type.KIND.BITFIELD

    ty_union: lief.pdb.types.Union = types[3970]
    assert isinstance(ty_union, lief.pdb.types.Union)
    assert ty_union.kind == lief.pdb.Type.KIND.UNION

    assert ty_union.to_decl() == dedent("""\
    union mbedtls_ssl_user_data_t {
        unsigned long long n;
        void p;
    }""")
    assert ty_union.name == "mbedtls_ssl_user_data_t"
    assert ty_union.size == 8

    assert pdb.find_type("LIEF::ELF::NONE") is None
    elf_bin: lief.pdb.types.Class = pdb.find_type("LIEF::ELF::Binary")
    assert elf_bin is not None

    assert elf_bin.unique_name == ".?AVBinary@ELF@LIEF@@"
    assert elf_bin.name == "LIEF::ELF::Binary"
    assert elf_bin.size == 576

    assert elf_bin.to_decl() == dedent("""\
    class LIEF::ELF::Binary {
        enum LIEF::ELF::ELF_CLASS type_;
        class LIEF::ELF::Header header_;
        class std::vector<std::unique_ptr<LIEF::ELF::Section,std::default_delete<LIEF::ELF::Section> >,std::allocator<std::unique_ptr<LIEF::ELF::Section,std::default_delete<LIEF::ELF::Section> > > > sections_;
        class std::vector<std::unique_ptr<LIEF::ELF::Segment,std::default_delete<LIEF::ELF::Segment> >,std::allocator<std::unique_ptr<LIEF::ELF::Segment,std::default_delete<LIEF::ELF::Segment> > > > segments_;
        class std::vector<std::unique_ptr<LIEF::ELF::DynamicEntry,std::default_delete<LIEF::ELF::DynamicEntry> >,std::allocator<std::unique_ptr<LIEF::ELF::DynamicEntry,std::default_delete<LIEF::ELF::DynamicEntry> > > > dynamic_entries_;
        class std::vector<std::unique_ptr<LIEF::ELF::Symbol,std::default_delete<LIEF::ELF::Symbol> >,std::allocator<std::unique_ptr<LIEF::ELF::Symbol,std::default_delete<LIEF::ELF::Symbol> > > > dynamic_symbols_;
        class std::vector<std::unique_ptr<LIEF::ELF::Symbol,std::default_delete<LIEF::ELF::Symbol> >,std::allocator<std::unique_ptr<LIEF::ELF::Symbol,std::default_delete<LIEF::ELF::Symbol> > > > static_symbols_;
        class std::vector<std::unique_ptr<LIEF::ELF::Relocation,std::default_delete<LIEF::ELF::Relocation> >,std::allocator<std::unique_ptr<LIEF::ELF::Relocation,std::default_delete<LIEF::ELF::Relocation> > > > relocations_;
        class std::vector<std::unique_ptr<LIEF::ELF::SymbolVersion,std::default_delete<LIEF::ELF::SymbolVersion> >,std::allocator<std::unique_ptr<LIEF::ELF::SymbolVersion,std::default_delete<LIEF::ELF::SymbolVersion> > > > symbol_version_table_;
        class std::vector<std::unique_ptr<LIEF::ELF::SymbolVersionRequirement,std::default_delete<LIEF::ELF::SymbolVersionRequirement> >,std::allocator<std::unique_ptr<LIEF::ELF::SymbolVersionRequirement,std::default_delete<LIEF::ELF::SymbolVersionRequirement> > > > symbol_version_requirements_;
        class std::vector<std::unique_ptr<LIEF::ELF::SymbolVersionDefinition,std::default_delete<LIEF::ELF::SymbolVersionDefinition> >,std::allocator<std::unique_ptr<LIEF::ELF::SymbolVersionDefinition,std::default_delete<LIEF::ELF::SymbolVersionDefinition> > > > symbol_version_definition_;
        class std::vector<std::unique_ptr<LIEF::ELF::Note,std::default_delete<LIEF::ELF::Note> >,std::allocator<std::unique_ptr<LIEF::ELF::Note,std::default_delete<LIEF::ELF::Note> > > > notes_;
        class std::unique_ptr<LIEF::ELF::GnuHash,std::default_delete<LIEF::ELF::GnuHash> > gnu_hash_;
        class std::unique_ptr<LIEF::ELF::SysvHash,std::default_delete<LIEF::ELF::SysvHash> > sysv_hash_;
        class std::unique_ptr<LIEF::ELF::DataHandler::Handler,std::default_delete<LIEF::ELF::DataHandler::Handler> > datahandler_;
        struct LIEF::ELF::Binary::phdr_relocation_info_t phdr_reloc_info_;
        class std::basic_string<char,std::char_traits<char>,std::allocator<char> > interpreter_;
        class std::vector<unsigned char,std::allocator<unsigned char> > overlay_;
        class std::unique_ptr<LIEF::ELF::sizing_info_t,std::default_delete<LIEF::ELF::sizing_info_t> > sizing_info_;
    }""")

    attrs = list(elf_bin.attributes)
    assert len(attrs) == 19

    assert attrs[0].name == "type_"
    assert attrs[0].field_offset == 24
    assert isinstance(attrs[0].type, lief.pdb.types.Enum)

    assert attrs[-1].name == "sizing_info_"
    assert attrs[-1].field_offset == 568
    assert isinstance(attrs[-1].type, lief.pdb.types.Class)

    methods = list(elf_bin.methods)
    assert len(methods) == 197
    assert methods[0].name == "operator="
    assert methods[1].name == "Binary"
    assert methods[196].name == "__vecDelDtor"
