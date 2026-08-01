import lief


def access_root(pe: lief.PE.Binary) -> None:
    # lief-doc: access-root-start
    pe: lief.PE.Binary
    rsrc = pe.resources

    print(rsrc)
    # lief-doc: access-root-end


def add_child(pe: lief.PE.Binary) -> None:
    # lief-doc: add-child-start
    pe: lief.PE.Binary

    rsrc = pe.resources
    assert isinstance(rsrc, lief.PE.ResourceNode)

    dir_node = lief.PE.ResourceDirectory(100)
    data_node = lief.PE.ResourceData([1, 2, 3])

    rsrc.add_child(dir_node).add_child(data_node)
    # lief-doc: add-child-end


def pretty_print(pe: lief.PE.Binary) -> None:
    # lief-doc: pretty-print-start
    pe: lief.PE.Binary

    tree = pe.resources
    print(tree)
    # lief-doc: pretty-print-end


def set_manifest(pe: lief.PE.Binary) -> None:
    # lief-doc: manifest-start
    pe: lief.PE.Binary

    manager = pe.resources_manager
    assert isinstance(manager, lief.PE.ResourcesManager)

    manager.manifest = """
    <?xml version="1.0" standalone="yes"?>
    <assembly xmlns="urn:schemas-microsoft-com:asm.v1"
              manifestVersion="1.0">
      <trustInfo>
        <security>
          <requestedPrivileges>
             <requestedExecutionLevel level='asInvoker' uiAccess='false'/>
          </requestedPrivileges>
        </security>
      </trustInfo>
    </assembly>
    """

    pe.write("new.exe")
    # lief-doc: manifest-end


def transfer_resources(from_pe: lief.PE.Binary, to_pe: lief.PE.Binary) -> None:
    # lief-doc: transfer-start
    from_pe: lief.PE.Binary
    to_pe: lief.PE.Binary

    resources = from_pe.resources
    assert isinstance(resources, lief.PE.ResourceNode)

    to_pe.set_resources(resources)
    to_pe.write("new.exe")
    # lief-doc: transfer-end
