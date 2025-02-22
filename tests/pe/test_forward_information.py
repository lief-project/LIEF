import lief
import json
from utils import get_sample

def test_basic():
    path = get_sample('PE/PE32_x86_library_kernel32.dll')
    sample = lief.PE.parse(path)
    exports = sample.get_export()
    forwarded_exports: list[lief.PE.ExportEntry] = [exp for exp in exports.entries if exp.is_forwarded]
    assert len(forwarded_exports) == 82

    assert forwarded_exports[0].name == "InterlockedPushListSList"
    assert forwarded_exports[0].forward_information.function == "RtlInterlockedPushListSList"
    assert forwarded_exports[0].forward_information.library == "NTDLL"

    print(exports)
    print(exports.entries[0])
    print(forwarded_exports)

    # Test JSON Serialization
    json_serialized = json.loads(lief.to_json(forwarded_exports[0]))

    assert "forward_information" in json_serialized
    assert json_serialized["forward_information"]["library"] == "NTDLL"
    assert json_serialized["forward_information"]["function"] == "RtlInterlockedPushListSList"

def test_issue_1168():
    input_path = get_sample('PE/user32.dll')
    pe = lief.PE.parse(input_path)
    fwd = [e for e in pe.get_export().entries if e.is_forwarded]
    assert len(fwd) == 4
    assert fwd[0].name == "DefDlgProcA"
    assert fwd[3].name == "DefWindowProcW"
