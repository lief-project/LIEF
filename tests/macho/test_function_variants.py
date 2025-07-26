import lief
from pathlib import Path
from utils import get_sample

# pyright: reportOptionalMemberAccess=false

def test_func_variants(tmp_path: Path):
    def check_variant(variant: lief.MachO.FunctionVariants):
        runtime_table = variant.runtime_table
        assert len(runtime_table) == 2

        assert runtime_table[0].kind == lief.MachO.FunctionVariants.RuntimeTable.KIND.X86_64
        assert runtime_table[0].offset == 16
        assert len(runtime_table[0].entries) == 3

        assert runtime_table[0].entries[0].impl == 0x0000056c
        assert runtime_table[0].entries[0].flags == [
            lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS.X86_64_ROSETTA,
        ]
        assert runtime_table[0].entries[1].impl == 0x00000590

        assert runtime_table[0].entries[1].flags == [
            lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS.X86_64_HASWELL,
        ]
        assert runtime_table[0].entries[2].impl == 0x000005b4

        assert runtime_table[0].entries[2].flags == []

        assert runtime_table[1].kind == lief.MachO.FunctionVariants.RuntimeTable.KIND.X86_64
        assert runtime_table[1].offset == 48
        assert len(runtime_table[1].entries) == 3

        assert runtime_table[1].entries[0].impl == 0x000005d8
        assert runtime_table[1].entries[0].flags == [
            lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS.X86_64_ROSETTA,
        ]
        assert runtime_table[1].entries[1].impl == 0x000005e0

        assert runtime_table[1].entries[1].flags == [
            lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS.X86_64_HASWELL,
        ]
        assert runtime_table[1].entries[2].impl == 0x000005e8

        assert runtime_table[1].entries[2].flags == []

    bin_path = Path(get_sample('MachO/variants_alt.dylib'))
    macho = lief.MachO.parse(bin_path.as_posix()).at(0)

    checked, err = lief.MachO.check_layout(macho)
    assert checked, err

    func_variants = macho.function_variants
    assert func_variants is not None
    raw_content = bytes(func_variants.content)
    assert raw_content.hex() == \
        "020000000c0000002c00000004000000030000006c050000080000009005000009000000b40" \
        "50000000000000400000003000000d805000008000000e005000009000000e8050000000000" \
        "0000000000"

    check_variant(func_variants)

    output = tmp_path / bin_path.name
    macho.write(output.as_posix())

    new = lief.MachO.parse(output).at(0)
    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    func_variants = new.function_variants
    assert func_variants is not None
    raw_content = bytes(func_variants.content)
    assert bytes(func_variants.content) == raw_content

    check_variant(func_variants)
