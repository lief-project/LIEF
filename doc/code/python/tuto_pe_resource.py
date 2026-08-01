import lief


def resource_section(binary: lief.PE.Binary) -> None:
    # lief-doc: resource-section-start
    binary: lief.PE.Binary

    if binary.has_resources:
        rsrc_directory = binary.data_directory(
            lief.PE.DataDirectory.TYPES.RESOURCE_TABLE
        )
        assert rsrc_directory is not None
        if rsrc_directory.has_section:
            print(rsrc_directory.section)
    # lief-doc: resource-section-end


def manifest_tree(filezilla: lief.PE.Binary) -> None:
    # lief-doc: manifest-tree-start
    filezilla: lief.PE.Binary

    root = filezilla.resources
    assert root is not None

    # First level => Type (ResourceDirectory node)
    manifest_node = next(
        i for i in root.childs if i.id == lief.PE.ResourcesManager.TYPE.MANIFEST
    )
    print(manifest_node)

    # Second level => ID (ResourceDirectory node)
    id_node = manifest_node.childs[0]
    print(id_node)

    # Third level => Lang (ResourceData node)
    lang_node = id_node.childs[0]
    print(lang_node)

    manifest = bytes(lang_node.content).decode("utf8")

    print(manifest)
    # lief-doc: manifest-tree-end


def overview(filezilla: lief.PE.Binary) -> None:
    # lief-doc: overview-start
    filezilla: lief.PE.Binar

    resource_manager = filezilla.resources_manager
    print(resource_manager)
    # lief-doc: overview-end


def get_manifest(filezilla: lief.PE.Binary) -> None:
    # lief-doc: get-manifest-start
    resources_manager = filezilla.resources_manager

    manifest = resources_manager.manifest
    print(manifest)
    # lief-doc: get-manifest-end


def set_admin(filezilla: lief.PE.Binary) -> None:
    # lief-doc: set-admin-start
    filezilla: lief.PE.Binary

    resources_manager = filezilla.resources_manager
    assert isinstance(resources_manager, lief.PE.ResourcesManager)

    manifest = resources_manager.manifest
    assert isinstance(manifest, str)

    manifest = manifest.replace("asInvoker", "requireAdministrator")
    resources_manager.manifest = manifest
    # lief-doc: set-admin-end


def load_managers() -> None:
    # lief-doc: load-managers-start
    mfc = lief.parse("mfc.exe")
    cmd = lief.parse("cmd.exe")

    mfc_rsrc_manager = mfc.resources_manager
    cmd_rsrc_manager = cmd.resources_manager
    # lief-doc: load-managers-end
    _ = (mfc_rsrc_manager, cmd_rsrc_manager)


def change_icons(
    mfc_rsrc_manager: lief.PE.ResourcesManager,
    cmd_rsrc_manager: lief.PE.ResourcesManager,
) -> None:
    # lief-doc: change-icons-start
    mfc_rsrc_manager: lief.PE.ResourcesManager
    cmd_rsrc_manager: lief.PE.ResourcesManager

    mfc_icons = mfc_rsrc_manager.icons
    cmd_icons = cmd_rsrc_manager.icons
    for i in range(min(len(mfc_icons), len(cmd_icons))):
        mfc_rsrc_manager.change_icon(mfc_icons[i], cmd_icons[i])
    # lief-doc: change-icons-end
