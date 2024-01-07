#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ctypes
import lief
import os
import random
import sys
import stat
import zipfile

from utils import get_sample, is_64bits_platform, is_windows, win_exec

if is_windows():
    SEM_NOGPFAULTERRORBOX = 0x0002  # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX)

def test_change_icons(tmp_path):
    mfc_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')
    mfc = lief.parse(mfc_path)
    mfc_resources_manger = mfc.resources_manager

    cmd_path = get_sample('PE/PE64_x86-64_binary_cmd.exe')
    cmd = lief.parse(cmd_path)
    cmd_resources_manger = cmd.resources_manager

    if not mfc_resources_manger.has_icons:
        print(f"'{mfc_path.name}' has no manifest. Abort!")
        sys.exit(1)

    if not cmd_resources_manger.has_icons:
        print(f"'{mfc_path.name}' has no manifest. Abort!")
        sys.exit(1)

    mfc_icons = mfc_resources_manger.icons
    cmd_icons = cmd_resources_manger.icons

    for i in range(min(len(mfc_icons), len(cmd_icons))):
        mfc_resources_manger.change_icon(mfc_icons[i], cmd_icons[i])

    output = tmp_path / "mfc_test_change_icon.exe"
    builder = lief.PE.Builder(mfc)
    builder.build_resources(True)
    builder.build()
    builder.write(output.as_posix())

    if ret := win_exec(output):
        ret_code, stdout = ret
        print(stdout)
        assert ret_code == 0

def test_resource_string_table():
    sample_path = get_sample('PE/PE64_x86-64_binary_WinApp.exe')
    mfc = lief.parse(sample_path)
    resources_manager = mfc.resources_manager

    assert resources_manager.has_string_table

    string_table = resources_manager.string_table
    assert string_table[0].name == "WinApp"
    assert string_table[0].length == 6

    assert string_table[1].name == "WINAPP"
    assert string_table[1].length == 6

def test_resource_accelerator():
    sample_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')
    mfc = lief.parse(sample_path)
    resources_manager = mfc.resources_manager

    assert resources_manager.has_accelerator

    accelerator = resources_manager.accelerator
    assert accelerator[0].flags == lief.PE.ACCELERATOR_FLAGS.FVIRTKEY | lief.PE.ACCELERATOR_FLAGS.FCONTROL
    assert accelerator[0].ansi == int(lief.PE.ACCELERATOR_VK_CODES.VK_N)
    assert accelerator[0].id == 0xe100
    assert accelerator[0].padding == 0

    assert accelerator[1].flags == lief.PE.ACCELERATOR_FLAGS.FVIRTKEY | lief.PE.ACCELERATOR_FLAGS.FCONTROL
    assert accelerator[1].ansi == int(lief.PE.ACCELERATOR_VK_CODES.VK_O)
    assert accelerator[1].id == 0xe101
    assert accelerator[1].padding == 0

    assert accelerator[2].flags == lief.PE.ACCELERATOR_FLAGS.FVIRTKEY | lief.PE.ACCELERATOR_FLAGS.FCONTROL
    assert accelerator[2].ansi == int(lief.PE.ACCELERATOR_VK_CODES.VK_S)
    assert accelerator[2].id == 0xe103
    assert accelerator[2].padding == 0

def test_resource_version():
    sample_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')
    mfc = lief.parse(sample_path)
    resources_manger = mfc.resources_manager

    assert resources_manger.has_version
    version = resources_manger.version

    assert version.type == 0
    assert version.key == 'VS_VERSION_INFO'

    assert version.has_string_file_info
    assert version.has_var_file_info
    assert version.has_fixed_file_info

    fixed_file_info  = version.fixed_file_info
    string_file_info = version.string_file_info
    var_file_info    = version.var_file_info

    # Check ResourceFixedFileInfo
    assert fixed_file_info.signature == 0xFEEF04BD
    assert fixed_file_info.struct_version == 0x10000
    assert fixed_file_info.file_version_MS == 0x010000
    assert fixed_file_info.file_version_LS == 0x000001
    assert fixed_file_info.product_version_MS == 0x010000
    assert fixed_file_info.product_version_LS == 0x000001
    assert fixed_file_info.file_flags_mask == 63
    assert fixed_file_info.file_flags == 0
    assert fixed_file_info.file_os == lief.PE.FIXED_VERSION_OS.NT_WINDOWS32
    assert fixed_file_info.file_type == lief.PE.FIXED_VERSION_FILE_TYPES.APP
    assert fixed_file_info.file_subtype == lief.PE.FIXED_VERSION_FILE_SUB_TYPES.UNKNOWN
    assert fixed_file_info.file_date_MS == 0
    assert fixed_file_info.file_date_LS == 0

    # Check ResourceStringFileInfo
    assert string_file_info.type == 1
    assert string_file_info.key == "StringFileInfo"
    assert len(string_file_info.langcode_items) == 1

    langcode_item = string_file_info.langcode_items[0]
    assert langcode_item.type == 1
    assert langcode_item.lang == lief.PE.RESOURCE_LANGS.FRENCH
    assert langcode_item.sublang == 1
    assert langcode_item.code_page == lief.PE.CODE_PAGES.UTF_16
    items = langcode_item.items
    assert 'CompanyName' in items
    assert items['CompanyName'] == b'TODO: <Nom de la soci\xc3\xa9t\xc3\xa9>'

    assert 'FileVersion' in items
    assert items['FileVersion'] == b'1.0.0.1'

    assert 'InternalName' in items
    assert items['InternalName'] == b'Hello.exe'

    assert 'LegalCopyright' in items
    assert items['LegalCopyright'].decode("utf8") == 'TODO: (c) <Nom de la société>.  Tous droits réservés.'

    assert 'OriginalFilename' in items
    assert items['OriginalFilename'] == b'Hello.exe'

    assert 'ProductName' in items
    assert items['ProductName'] == b'TODO: <Nom du produit>'

    assert 'ProductVersion' in items
    assert items['ProductVersion'] == b'1.0.0.1'

    # Check ResourceVarFileInfo
    assert var_file_info.type == 1
    assert var_file_info.key == "VarFileInfo"
    assert len(var_file_info.translations) == 1
    assert var_file_info.translations[0] == 0x4b0040c

def test_resource_dialogs():
    evince_path = get_sample('PE/PE32_x86_binary_EvincePortable.zip')
    evince: lief.PE.Binary = None
    with zipfile.ZipFile(evince_path, "r") as inz:
        for f in inz.infolist():
            if f.filename != "EvincePortable/EvincePortable.exe":
                continue
            fbytes = inz.read(f.filename)
            evince = lief.parse(fbytes)
    manager = evince.resources_manager

    if is_64bits_platform():
        assert lief.hash(manager.manifest) == 16239254889843919593
    assert len(manager.dialogs) == 15

    dialog = manager.dialogs[0]

    assert dialog.help_id == 0x1
    assert dialog.x == 0x0
    assert dialog.y == 0x0
    assert dialog.cx == 0x118
    assert dialog.cy == 0xa2
    assert dialog.title == ""
    assert dialog.typeface == "MS Shell Dlg"
    assert dialog.weight == 0x0
    assert dialog.point_size == 0x8
    assert dialog.charset == 0x1
    assert dialog.style == 0x0
    assert dialog.lang == lief.PE.RESOURCE_LANGS.ENGLISH
    assert dialog.sub_lang == 1
    assert len(dialog.items) == 6

    assert dialog.items[0].help_id == 0x0
    assert dialog.items[0].extended_style == 0x0
    assert dialog.items[0].style == 0x40030000
    assert dialog.items[0].x == 0xab
    assert dialog.items[0].y == 0x8e
    assert dialog.items[0].cx == 0x32
    assert dialog.items[0].cy == 0xe
    assert dialog.items[0].id == 0x3
    assert dialog.items[0].title == ""


    assert dialog.items[1].help_id == 0x0
    assert dialog.items[1].extended_style == 0x0
    assert dialog.items[1].style == 0x50010000
    assert dialog.items[1].x == 0xdf
    assert dialog.items[1].y == 0x8e
    assert dialog.items[1].cx == 0x32
    assert dialog.items[1].cy == 0xe
    assert dialog.items[1].id == 0x1
    assert dialog.items[1].title == ""

    assert dialog.items[2].help_id == 0x0
    assert dialog.items[2].extended_style == 0x0
    assert dialog.items[2].style == 0x50010000
    assert dialog.items[2].x == 0x7
    assert dialog.items[2].y == 0x8e
    assert dialog.items[2].cx == 0x32
    assert dialog.items[2].cy == 0xe
    assert dialog.items[2].id == 0x2
    assert dialog.items[2].title == ""

    assert dialog.items[5].help_id == 0x0
    assert dialog.items[5].extended_style == 0x0
    assert dialog.items[5].style == 0x58020001
    assert dialog.items[5].x == 0x3b
    assert dialog.items[5].y == 0x91
    assert dialog.items[5].cx == 0x6c
    assert dialog.items[5].cy == 0x8
    assert dialog.items[5].id == 0x404
    assert dialog.items[5].title == ""

def test_mfc_resource_builder(tmp_path):
    sample_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')
    output      = tmp_path / "mfc_test_rsrc.exe"

    mfc = lief.parse(sample_path)

    builder = lief.PE.Builder(mfc)
    builder.build_resources(True)
    builder.build()
    builder.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    if ret := win_exec(output):
        ret_code, stdout = ret
        print(stdout)
        assert ret_code == 0

#def test_evince_resource_builder(self):
#    sample_file = get_sample('PE/PE32_x86_binary_EvincePortable.zip')
#    sample_dir  = os.path.join(self.tmp_dir, "EvincePortable")

#    sample = os.path.join(sample_dir, "EvincePortable.exe")
#    output = os.path.join(sample_dir, "evince_rsrc.exe")

#    zip_ref = zipfile.ZipFile(sample_file, 'r')
#    zip_ref.extractall(self.tmp_dir)
#    zip_ref.close()

#    evince = lief.parse(sample)

#    builder = lief.PE.Builder(evince)
#    builder.build_resources(True)
#    builder.build()
#    builder.write(output)

#    st = os.stat(output)
#    os.chmod(output, st.st_mode | stat.S_IEXEC)

#    if sys.platform.startswith("win"):
#        subprocess_flags = 0x8000000 # win32con.CREATE_NO_WINDOW?
#        p = Popen(["START", output], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=subprocess_flags)
#        time.sleep(3)
#        q = Popen(["taskkill", "/im", "evince_rsrc.exe"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

#        stdout, _ = p.communicate()
#        print(stdout.decode("utf8"))

#        stdout, _ = q.communicate()
#        print(stdout.decode("utf8"))

#        assert q.returncode == 0

def test_notepadpp_resource_builder(tmp_path):
    sample_file = get_sample('PE/PE32_x86_binary_Notepad++.zip')
    sample_dir  = tmp_path / "Notepad++"

    sample = sample_dir / "notepad++.exe"
    output = sample_dir / "notepad++_rsrc.exe"

    with zipfile.ZipFile(sample_file, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)

    notepadpp = lief.parse(sample.as_posix())

    builder = lief.PE.Builder(notepadpp)
    builder.build_resources(True)
    builder.build()
    builder.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    if ret := win_exec(output):
        ret_code, stdout = ret
        print(stdout)
        assert ret_code == 0

def test_filezilla_resource_builder(tmp_path):
    sample_file = get_sample('PE/PE64_x86-64_binary_FileZilla.zip')
    sample_dir  = tmp_path / "FileZilla"

    sample = sample_dir / "filezilla.exe"
    output = sample_dir / "filezilla_rsrc.exe"

    with zipfile.ZipFile(sample_file, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)

    filezilla = lief.parse(sample.as_posix())

    builder = lief.PE.Builder(filezilla)
    builder.build_resources(True)
    builder.build()
    builder.write(output.as_posix())

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    if ret := win_exec(output):
        ret_code, stdout = ret
        print(stdout)
        assert ret_code == 0

def test_resource_directory_add_directory_node(tmp_path):
    sample_file = get_sample('PE/PE32_x86_binary_Notepad++.zip')
    sample_dir  = tmp_path / "Notepad++"

    sample = sample_dir / "notepad++.exe"

    with zipfile.ZipFile(sample_file, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)

    for seed in (5, 20, 99):
        app = lief.parse(sample.as_posix())
        assert [child.id for child in app.resources.childs] == [1, 2, 3, 4, 5, 6, 12, 14, 16, 24]
        nodes = []

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.HTML
        nodes.append(node)

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.RCDATA
        nodes.append(node)

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.FONT
        nodes.append(node)

        # Deterministically shuffle the add order with the seed
        random.Random(seed).shuffle(nodes)

        for node in nodes:
            new_node = app.resources.add_directory_node(node)
            assert isinstance(new_node, lief.PE.ResourceNode)

        # Should be in sorted order by ID
        assert [child.id for child in app.resources.childs] == [1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 23, 24]

    for seed in (7, 23, 91):
        app = lief.parse(sample.as_posix())
        assert lief.PE.ResourcesManager.TYPE.RCDATA.value not in [child.id for child in app.resources.childs]

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.RCDATA
        rcdata_node = app.resources.add_directory_node(node)
        assert isinstance(rcdata_node, lief.PE.ResourceNode)

        assert len(rcdata_node.childs) == 0
        nodes = []

        node = lief.PE.ResourceDirectory()
        node.id = 10
        nodes.append(node)

        node = lief.PE.ResourceDirectory()
        node.name = "FOO"
        node.id = 0x80000000
        nodes.append(node)

        node = lief.PE.ResourceDirectory()
        node.id = 5
        nodes.append(node)

        node = lief.PE.ResourceDirectory()
        node.id = 99
        nodes.append(node)

        node = lief.PE.ResourceDirectory()
        node.name = "bar"
        node.id = 0x80000000
        nodes.append(node)

        node = lief.PE.ResourceDirectory()
        node.name = "foo"
        node.id = 0x80000000
        nodes.append(node)

        # Deterministically shuffle the add order with the seed
        random.Random(seed).shuffle(nodes)

        for node in nodes:
            new_node = rcdata_node.add_directory_node(node)
            assert isinstance(new_node, lief.PE.ResourceNode)

        # Should be in sorted order with names first, then IDs
        assert [child.name or child.id for child in rcdata_node.childs] == ["FOO", "bar", "foo", 5, 10, 99]

def test_resource_directory_add_data_node(tmp_path):
    sample_file = get_sample('PE/PE32_x86_binary_Notepad++.zip')
    sample_dir  = tmp_path / "Notepad++"

    sample = sample_dir / "notepad++.exe"

    with zipfile.ZipFile(sample_file, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)

    for seed in (7, 23, 91):
        app = lief.parse(sample.as_posix())
        assert lief.PE.ResourcesManager.TYPE.RCDATA.value not in [child.id for child in app.resources.childs]

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.RCDATA
        rcdata_node = app.resources.add_directory_node(node)
        assert isinstance(rcdata_node, lief.PE.ResourceNode)

        node = lief.PE.ResourceDirectory()
        node.id = 10
        lang_node = rcdata_node.add_directory_node(node)

        assert len(lang_node.childs) == 0
        nodes = []

        for id_ in (1033, 44, 500, 0):
            node = lief.PE.ResourceData()
            node.id = id_
            nodes.append(node)

        # Deterministically shuffle the add order with the seed
        random.Random(seed).shuffle(nodes)

        for node in nodes:
            new_node = lang_node.add_data_node(node)
            assert isinstance(new_node, lief.PE.ResourceNode)

        # Should be in sorted order
        assert [child.name or child.id for child in lang_node.childs] == [0, 44, 500, 1033]

def test_nodes(tmp_path):
    sample_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')
    output      = tmp_path / "mfc_test_rsrc.exe"

    mfc = lief.PE.parse(sample_path)
    assert mfc.resources is not None
    node = mfc.resources

    assert mfc.resources_manager == lief.PE.ResourcesManager(mfc.resources)

    assert isinstance(node, lief.PE.ResourceDirectory)
    assert node.depth == 0
    assert len(node.childs) == 10
    assert node.name == ""
    assert node.is_directory
    assert not node.is_data
    assert not node.has_name
    node.delete_child(1000000)
    node.name = "Hello"
    assert node.name == "Hello"
    assert node.copy() == node
    assert hash(node.copy()) == hash(node)
    print(node)

    # Find data node
    current = node
    while not current.is_data:
        if len(current.childs) == 0:
            break
        for child in current.childs:
            current = child
            break

    assert current is not None
    assert isinstance(current, lief.PE.ResourceData)
    assert current.is_data
    data_node: lief.PE.ResourceData = current
    print(data_node)
    assert data_node.reserved == 0
    assert data_node.offset == 204224
    assert data_node.code_page == 0
    assert len(data_node.content) == 1064
    assert data_node.copy() == data_node
    assert hash(data_node.copy()) == hash(data_node)
