import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_lief():
    pdb = lief.pdb.load(get_sample("private/PDB/LIEF.pdb"))

    types = list(pdb.types)
    assert len(types) == 116669

    ty_modifier: lief.pdb.types.Modifier = types[0]
    assert isinstance(ty_modifier, lief.pdb.types.Modifier)
    assert ty_modifier.kind == lief.pdb.Type.KIND.MODIFIER
    underlying: lief.pdb.types.Simple = ty_modifier.underlying_type
    assert isinstance(underlying, lief.pdb.types.Simple)
    assert underlying.kind == lief.pdb.Type.KIND.SIMPLE

    ty_pointer: lief.pdb.types.Pointer = types[7]
    assert isinstance(ty_pointer, lief.pdb.types.Pointer)
    assert ty_pointer.kind == lief.pdb.Type.KIND.POINTER

    underlying: lief.pdb.types.Modifier = ty_pointer.underlying_type
    assert isinstance(underlying, lief.pdb.types.Modifier)
    assert underlying.kind == lief.pdb.Type.KIND.MODIFIER

    ty_function: lief.pdb.types.Function = types[10]
    assert isinstance(ty_function, lief.pdb.types.Function)
    assert ty_function.kind == lief.pdb.Type.KIND.FUNCTION

    ty_enum: lief.pdb.types.Enum = types[11]
    assert isinstance(ty_enum, lief.pdb.types.Enum)
    assert ty_enum.kind == lief.pdb.Type.KIND.ENUM

    ty_struct: lief.pdb.types.Structure = types[19]
    assert isinstance(ty_struct, lief.pdb.types.Structure)
    assert ty_struct.kind == lief.pdb.Type.KIND.STRUCTURE

    ty_array: lief.pdb.types.Array = types[154]
    assert isinstance(ty_array, lief.pdb.types.Array)
    assert ty_array.kind == lief.pdb.Type.KIND.ARRAY

    ty_bf: lief.pdb.types.BitField = types[3925]
    assert isinstance(ty_bf, lief.pdb.types.BitField)
    assert ty_bf.kind == lief.pdb.Type.KIND.BITFIELD

    ty_union: lief.pdb.types.Union = types[3970]
    assert isinstance(ty_union, lief.pdb.types.Union)
    assert ty_union.kind == lief.pdb.Type.KIND.UNION

    assert pdb.find_type("LIEF::ELF::NONE") is None
    elf_bin: lief.pdb.types.Class = pdb.find_type("LIEF::ELF::Binary")
    assert elf_bin is not None

    assert elf_bin.unique_name == ".?AVBinary@ELF@LIEF@@"
    assert elf_bin.name == "LIEF::ELF::Binary"
    assert elf_bin.size == 576

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
