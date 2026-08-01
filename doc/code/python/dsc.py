import lief


def load() -> lief.dsc.DyldSharedCache | None:
    # lief-doc: load-start
    dyld_cache: lief.dsc.DyldSharedCache | None = lief.dsc.load("macos-15.0.1/")
    # lief-doc: load-end
    return dyld_cache


def iterate_libraries(dyld_cache: lief.dsc.DyldSharedCache) -> None:
    # lief-doc: libraries-start
    dyld_cache: lief.dsc.DyldSharedCache

    for dylib in dyld_cache.libraries:
        print(f"{dylib.address:#016x}: {dylib.path}")
    # lief-doc: libraries-end


def extract(dyld_cache: lief.dsc.DyldSharedCache) -> None:
    # lief-doc: extract-start
    dyld_cache: lief.dsc.DyldSharedCache

    liblockdown = dyld_cache.find_lib_from_name("liblockdown.dylib")

    macho = liblockdown.get()

    for segment in macho.segments:
        print(segment.name)
    # lief-doc: extract-end


def write_back(dyld_cache: lief.dsc.DyldSharedCache) -> None:
    # lief-doc: write-start
    dyld_cache: lief.dsc.DyldSharedCache

    liblockdown = dyld_cache.find_lib_from_name("liblockdown.dylib")

    macho = liblockdown.get()
    macho.write("on-disk-liblockdown.dylib")
    # lief-doc: write-end


def random_access(dyld_cache: lief.dsc.DyldSharedCache) -> lief.dsc.Dylib | None:
    # lief-doc: random-access-start
    dyld_cache: lief.dsc.DyldSharedCache

    # No cost
    libraries = dyld_cache.libraries

    # O(1) cost
    first_lib = libraries[0]

    # O(len(libraries)) cost
    for lib in libraries:
        print(lib.path)
    # lief-doc: random-access-end
    return first_lib
