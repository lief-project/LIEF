# ruff: noqa: BLE001
import lief


def get_type_exception() -> lief.PE.PE_TYPE | lief.lief_errors | None:
    pe_type: lief.PE.PE_TYPE | lief.lief_errors | None = None
    # lief-doc: get-type-exception-start
    try:
        pe_type = lief.PE.get_type("/tmp/NotPE.elf")
        # If it does not fail, pe_type handles a lief.PE.PE_TYPE object
    except Exception as e:
        print(f"Error: {e}")
    # lief-doc: get-type-exception-end
    return pe_type


def get_type_error() -> None:
    # lief-doc: get-type-error-start
    pe_type = lief.PE.get_type("/tmp/NotPE.elf")

    if pe_type == lief.lief_errors.file_error:
        print("File error")
    elif isinstance(pe_type, lief.lief_errors):
        print("Another kind of error")
    else:
        print(f"No error, type is: {pe_type}")
    # lief-doc: get-type-error-end
