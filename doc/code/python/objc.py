import lief


def check(macho: lief.MachO.Binary) -> None:
    # lief-doc: check-start
    macho: lief.MachO.Binary

    metadata = macho.objc_metadata
    if metadata is not None:
        print("Objective-C metadata found")
    # lief-doc: check-end


def inspect(macho: lief.MachO.Binary) -> None:
    # lief-doc: inspect-start
    macho: lief.MachO.Binary

    metadata = macho.objc_metadata
    for clazz in metadata.classes:
        print(f"name={clazz.name}")
        for meth in clazz.methods:
            print(f"  method.name={meth.name}")
    print(metadata.to_decl())
    # lief-doc: inspect-end


# lief-doc: no-address-start
def print_without_address(macho: lief.MachO.Binary):

    metadata = macho.objc_metadata

    config = lief.objc.DeclOpt()
    config.show_annotations = False

    for cls in metadata.classes:
        print(cls.to_decl(config))


# lief-doc: no-address-end
