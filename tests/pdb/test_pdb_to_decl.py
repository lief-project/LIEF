import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_declopt():
    opt = lief.DeclOpt()

    # Defaults
    assert opt.indentation == 2
    assert opt.is_cpp is False
    assert opt.show_extended_annotations is True
    assert opt.include_types is False
    assert opt.include_locals is False
    assert opt.desugar is True
    assert opt.show_field_offsets is False
    assert dict(opt.type_aliases) == {}

    # Setters round-trip (pimpl)
    opt.indentation = 4
    opt.is_cpp = True
    opt.show_extended_annotations = False
    opt.include_types = True
    opt.include_locals = True
    opt.desugar = False
    opt.show_field_offsets = True
    opt.add_type_alias("std::__cxx11::basic_string", "std::string")

    assert opt.indentation == 4
    assert opt.is_cpp is True
    assert opt.show_extended_annotations is False
    assert opt.include_types is True
    assert opt.include_locals is True
    assert opt.desugar is False
    assert opt.show_field_offsets is True
    assert dict(opt.type_aliases) == {"std::__cxx11::basic_string": "std::string"}


def test_function_and_compilation_unit():
    pdb = lief.pdb.load(get_sample("private/PDB/LIEF.pdb"))
    assert isinstance(pdb, lief.pdb.DebugInfo)

    func = None
    cu = None
    for unit in pdb.compilation_units:
        assert unit is not None
        functions = list(unit.functions)
        if functions:
            cu = unit
            func = functions[0]
            break

    assert func is not None, "expected at least one function in the PDB"
    assert cu is not None

    # pdb.Function.to_decl
    fn_decl = func.to_decl()
    assert isinstance(fn_decl, str)
    assert len(fn_decl) > 0

    name = func.name.split("(")[0].rsplit("::", 1)[-1]
    assert name
    assert name in fn_decl

    cu_decl = cu.to_decl()
    assert isinstance(cu_decl, str)
    assert len(cu_decl) > 0
    assert name in cu_decl

    opt = lief.DeclOpt()
    opt.is_cpp = True
    assert isinstance(func.to_decl(opt), str)
    assert isinstance(cu.to_decl(opt), str)
