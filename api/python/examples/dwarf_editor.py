"""
This example shows how to create a DWARF file by using LIEF's Python API
"""
import lief
import sys

if not lief.__extended__:
    print("This example requires the extended version of LIEF")

pe = lief.PE.parse(sys.argv[1])
editor: lief.dwarf.Editor = lief.dwarf.Editor.from_binary(pe)

unit: lief.dwarf.editor.CompilationUnit = editor.create_compilation_unit()
unit.set_producer("LIEF")

func: lief.dwarf.editor.Function = unit.create_function("hello")
func.set_address(0x123)
func.set_return_type(
    unit.create_structure("my_struct_t").pointer_to()
)

var: lief.dwarf.editor.Variable = func.create_stack_variable("local_var")
var.set_stack_offset(8)

editor.write("/tmp/out.debug")
