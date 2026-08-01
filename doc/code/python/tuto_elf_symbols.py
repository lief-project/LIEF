import lief


def imported_exported(binary: lief.Binary, library: lief.Binary) -> None:
    # lief-doc: imported-exported-start
    binary: lief.Binary
    library: lief.Binary

    print(binary.imported_functions)
    print(library.exported_functions)
    # lief-doc: imported-exported-end


def load_binaries() -> None:
    # lief-doc: load-start

    hashme = lief.parse("hashme")
    libm = lief.parse("/usr/lib/libm.so.6")
    # Note: the path to libm.so.6 might be different on your system.
    # lief-doc: load-end
    _ = (hashme, libm)


def change_imported(hashme: lief.ELF.Binary) -> None:
    # lief-doc: change-imported-start
    hashme: lief.ELF.Binary

    hashme_pow_sym = next(i for i in hashme.imported_symbols if i.name == "pow")
    hashme_log_sym = next(i for i in hashme.imported_symbols if i.name == "log")

    hashme_pow_sym.name = "cos"
    hashme_log_sym.name = "sin"
    # lief-doc: change-imported-end


def swap_all(hashme: lief.ELF.Binary, libm: lief.ELF.Binary) -> None:
    # lief-doc: swap-all-start
    def swap(obj, a, b):
        symbol_a = next(i for i in obj.dynamic_symbols if i.name == a)
        symbol_b = next(i for i in obj.dynamic_symbols if i.name == b)
        b_name = symbol_b.name
        symbol_b.name = symbol_a.name
        symbol_a.name = b_name

    hashme: lief.ELF.Binary
    libm: lief.ELF.Binary

    hashme_pow_sym = next(i for i in hashme.imported_symbols if i.name == "pow")
    hashme_log_sym = next(i for i in hashme.imported_symbols if i.name == "log")

    hashme_pow_sym.name = "cos"
    hashme_log_sym.name = "sin"

    swap(libm, "log", "sin")
    swap(libm, "pow", "cos")

    hashme.write("hashme.obf")
    libm.write("libm.so.6")
    # lief-doc: swap-all-end
