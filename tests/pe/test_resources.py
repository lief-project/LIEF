#!/usr/bin/env python

import ctypes
import lief
import random
import sys
import zipfile
import pytest
from textwrap import dedent

from utils import (
    get_sample, is_64bits_platform, is_windows, win_exec, is_x86_64,
    has_private_samples
)

from pathlib import Path
from hashlib import md5

if is_windows():
    SEM_NOGPFAULTERRORBOX = 0x0002  # From MSDN
    ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX) # type: ignore

def _dump_icon(icon: lief.PE.ResourceIcon):
    raw = icon.serialize()
    lines = []
    tmp: list[str] = []
    for idx, byte in enumerate(raw):
        if idx % 26 == 0 and idx != 0:
            lines.append(tmp)
            tmp = []
            tmp.append(f"{byte:02x}")
        else:
            tmp.append(f"{byte:02x}")

    if len(tmp) > 0:
        lines.append(tmp)

    for line in lines:
        print(":".join(line))

def quick_hash(content: memoryview) -> str:
    return md5(content).hexdigest()

def test_change_icons():
    mfc_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')
    mfc = lief.PE.parse(mfc_path)
    mfc_resources_manger = mfc.resources_manager
    assert isinstance(mfc_resources_manger, lief.PE.ResourcesManager)

    cmd_path = get_sample('PE/PE64_x86-64_binary_cmd.exe')
    cmd = lief.PE.parse(cmd_path)
    cmd_resources_manger = cmd.resources_manager
    assert isinstance(cmd_resources_manger, lief.PE.ResourcesManager)

    if not mfc_resources_manger.has_icons:
        print(f"'{mfc_path.name}' has no manifest. Abort!")
        sys.exit(1)

    if not cmd_resources_manger.has_icons:
        print(f"'{mfc_path.name}' has no manifest. Abort!")
        sys.exit(1)

    mfc_icons = mfc_resources_manger.icons
    cmd_icons = cmd_resources_manger.icons

    id_map = {}

    for i in range(min(len(mfc_icons), len(cmd_icons))):
        id_map[cmd_icons[i].id] = quick_hash(cmd_icons[i].pixels)
        mfc_resources_manger.change_icon(mfc_icons[i], cmd_icons[i])

    new_raw_pe = mfc.write_to_bytes()
    new_pe = lief.PE.parse(list(new_raw_pe))
    new_manager = new_pe.resources_manager
    assert isinstance(new_manager, lief.PE.ResourcesManager)

    icons = list(new_manager.icons)

    for ico in icons:
        pixel_hash = id_map.get(ico.id)
        if pixel_hash is not None:
            assert pixel_hash == quick_hash(ico.pixels)

    assert cmd.resources != new_pe.resources
    assert mfc.resources == new_pe.resources

def test_resource_string_table():
    sample_path = get_sample('PE/PE64_x86-64_binary_WinApp.exe')
    mfc = lief.PE.parse(sample_path)
    resources_manager = mfc.resources_manager
    assert isinstance(resources_manager, lief.PE.ResourcesManager)

    assert resources_manager.has_string_table

    string_table = resources_manager.string_table
    assert string_table[0].string == "WinApp"
    assert string_table[0].id == 103

    assert string_table[1].string == "WINAPP"
    assert string_table[1].id == 109

def test_resource_accelerator():
    sample_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')
    mfc = lief.PE.parse(sample_path)
    resources_manager = mfc.resources_manager
    assert isinstance(resources_manager, lief.PE.ResourcesManager)

    assert resources_manager.has_accelerator

    accelerator = resources_manager.accelerator
    assert accelerator[0].flags == lief.PE.ResourceAccelerator.FLAGS.VIRTKEY | lief.PE.ResourceAccelerator.FLAGS.CONTROL
    assert accelerator[0].ansi == lief.PE.ACCELERATOR_CODES.N.value
    assert accelerator[0].id == 0xe100
    assert accelerator[0].padding == 0

    assert accelerator[1].flags == lief.PE.ResourceAccelerator.FLAGS.VIRTKEY | lief.PE.ResourceAccelerator.FLAGS.CONTROL
    assert accelerator[1].ansi == lief.PE.ACCELERATOR_CODES.O.value
    assert accelerator[1].id == 0xe101
    assert accelerator[1].padding == 0

    assert accelerator[2].flags == lief.PE.ResourceAccelerator.FLAGS.VIRTKEY | lief.PE.ResourceAccelerator.FLAGS.CONTROL
    assert accelerator[2].ansi == lief.PE.ACCELERATOR_CODES.S.value
    assert accelerator[2].id == 0xe103
    assert accelerator[2].padding == 0

def test_resource_version():
    input_path = Path(get_sample('PE/steam.exe'))
    pe = lief.PE.parse(input_path)
    manager = pe.resources_manager

    assert isinstance(manager, lief.PE.ResourcesManager)

    versions = list(manager.version)
    assert len(versions) == 2

    v1 = versions[0]
    assert v1.key == "VS_VERSION_INFO"
    assert v1.type == 0
    assert v1.file_info.signature == 0xfeef04bd
    assert v1.file_info.struct_version == 0x10000
    assert v1.file_info.file_version_ms == 458833
    assert v1.file_info.file_version_ls == 65600
    assert v1.file_info.product_version_ms == 65536
    assert v1.file_info.product_version_ls == 2
    assert v1.file_info.file_flags_mask == 23
    assert v1.file_info.file_flags == 0
    assert v1.file_info.file_os == 4
    assert v1.file_info.file_type == 1
    assert v1.file_info.file_subtype == 0
    assert v1.file_info.file_date_ms == 0
    assert v1.file_info.file_date_ls == 0

    assert v1.string_file_info.key == 'StringFileInfo'
    assert v1.string_file_info.type == 1
    assert len(v1.string_file_info.children) == 1
    assert v1.string_file_info.children[0].key == "040904b0"
    assert v1.string_file_info.children[0].type == 0
    assert len(v1.string_file_info.children[0].entries) == 9

    assert v1.string_file_info.children[0].entries[0].key == "LegalCopyright"
    assert v1.string_file_info.children[0].entries[0].value == "Copyright (C) 2021 Valve Corporation"

    assert v1.string_file_info.children[0].entries[1].key == "InternalName"
    assert v1.string_file_info.children[0].entries[1].value == "steam (buildbot_steam-relclient-win32-builder_steam_rel_client_win32@steam-relclient-win32-builder)"

    assert v1.string_file_info.children[0].entries[2].key == "FileVersion"
    assert v1.string_file_info.children[0].entries[2].value == "07.81.01.64"

    assert v1.string_file_info.children[0].entries[3].key == "CompanyName"
    assert v1.string_file_info.children[0].entries[3].value == "Valve Corporation"

    assert v1.string_file_info.children[0].entries[4].key == "ProductVersion"
    assert v1.string_file_info.children[0].entries[4].value == "01.00.00.02"

    assert v1.string_file_info.children[0].entries[5].key == "FileDescription"
    assert v1.string_file_info.children[0].entries[5].value == "Steam"

    assert v1.string_file_info.children[0].entries[6].key == "Source Control ID"
    assert v1.string_file_info.children[0].entries[6].value == "7810164"

    assert v1.string_file_info.children[0].entries[7].key == "OriginalFilename"
    assert v1.string_file_info.children[0].entries[7].value == "steam.exe"

    assert v1.string_file_info.children[0].entries[8].key == "ProductName"
    assert v1.string_file_info.children[0].entries[8].value == "Steam"

    assert v1.var_file_info.key == "VarFileInfo"
    assert v1.var_file_info.type == 1
    assert len(v1.var_file_info.vars) == 1
    assert v1.var_file_info.vars[0].key == 'Translation'
    assert v1.var_file_info.vars[0].type == 0
    assert len(v1.var_file_info.vars[0].values) == 1
    assert v1.var_file_info.vars[0].values[0] == 78644233

    v2 = versions[1]
    assert v2.key == "VS_VERSION_INFO"
    assert v2.type == 0
    assert v2.file_info.signature == 0xfeef04bd
    assert v2.file_info.struct_version == 0x10000
    assert v2.file_info.file_version_ms == 0x10000
    assert v2.file_info.file_version_ls == 2
    assert v2.file_info.product_version_ms == 65536
    assert v2.file_info.product_version_ls == 2
    assert v2.file_info.file_flags_mask == 23
    assert v2.file_info.file_flags == 0
    assert v2.file_info.file_os == 4
    assert v2.file_info.file_type == 1
    assert v2.file_info.file_subtype == 0
    assert v2.file_info.file_date_ms == 0
    assert v2.file_info.file_date_ls == 0

    assert v2.string_file_info.key == 'StringFileInfo'
    assert v2.string_file_info.type == 1
    assert len(v2.string_file_info.children) == 1
    assert v2.string_file_info.children[0].key == "040904b0"
    assert v2.string_file_info.children[0].type == 0
    assert len(v2.string_file_info.children[0].entries) == 8

    assert v2.string_file_info.children[0].entries[0].key == "CompanyName"
    assert v2.string_file_info.children[0].entries[0].value == "Valve Corporation"

    assert v2.string_file_info.children[0].entries[1].key == "FileDescription"
    assert v2.string_file_info.children[0].entries[1].value == "Steam"

    assert v2.string_file_info.children[0].entries[2].key == "FileVersion"
    assert v2.string_file_info.children[0].entries[2].value == "1, 0, 0, 2"

    assert v2.string_file_info.children[0].entries[3].key == "InternalName"
    assert v2.string_file_info.children[0].entries[3].value == "steam"

    assert v2.string_file_info.children[0].entries[4].key == "LegalCopyright"
    assert v2.string_file_info.children[0].entries[4].value == "Copyright (C) 2021 Valve Corporation"

    assert v2.string_file_info.children[0].entries[5].key == "OriginalFilename"
    assert v2.string_file_info.children[0].entries[5].value == "steam.exe"

    assert v2.string_file_info.children[0].entries[6].key == "ProductName"
    assert v2.string_file_info.children[0].entries[6].value == "Steam"

    assert v2.string_file_info.children[0].entries[7].key == "ProductVersion"
    assert v2.string_file_info.children[0].entries[7].value == "1, 0, 0, 2"

    assert v2.var_file_info.key == "VarFileInfo"
    assert v2.var_file_info.type == 1
    assert len(v2.var_file_info.vars) == 1
    assert v2.var_file_info.vars[0].key == 'Translation'
    assert v2.var_file_info.vars[0].type == 0
    assert len(v2.var_file_info.vars[0].values) == 1
    assert v2.var_file_info.vars[0].values[0] == 0x04B00409

    # To be enabled?
    #if is_64bits_platform():
    #    assert lief.hash(v1) == 18317000971015120503
    #    assert lief.hash(v2) == 6262581342140742046

    assert str(v1) == dedent("""\
    Struct Version      : 0x010000
    File version        : 7-81-1-64
    Product version     : 1-0-0-2
    File OS             : WINDOWS32 (0x00000004)
    File Type           : APP (0x00000001)
    BLOCK 'StringFileInfo' {
      BLOCK '040904b0' {
        LegalCopyright: Copyright (C) 2021 Valve Corporation
        InternalName: steam (buildbot_steam-relclient-win32-builder_steam_rel_client_win32@steam-relclient-win32-builder)
        FileVersion: 07.81.01.64
        CompanyName: Valve Corporation
        ProductVersion: 01.00.00.02
        FileDescription: Steam
        Source Control ID: 7810164
        OriginalFilename: steam.exe
        ProductName: Steam
      }
    }
    BLOCK 'VarFileInfo' {
      Translation: 0x04b00409
    }
    """)

    assert str(v2) == dedent("""\
    Struct Version      : 0x010000
    File version        : 1-0-0-2
    Product version     : 1-0-0-2
    File OS             : WINDOWS32 (0x00000004)
    File Type           : APP (0x00000001)
    BLOCK 'StringFileInfo' {
      BLOCK '040904b0' {
        CompanyName: Valve Corporation
        FileDescription: Steam
        FileVersion: 1, 0, 0, 2
        InternalName: steam
        LegalCopyright: Copyright (C) 2021 Valve Corporation
        OriginalFilename: steam.exe
        ProductName: Steam
        ProductVersion: 1, 0, 0, 2
      }
    }
    BLOCK 'VarFileInfo' {
      Translation: 0x04b00409
    }
    """)

def test_resource_dialogs_regular():
    input_path = Path(get_sample("PE/chnginbx.exe"))

    pe = lief.PE.parse(input_path)

    manager = pe.resources_manager
    assert isinstance(manager, lief.PE.ResourcesManager)
    dialogs = list(manager.dialogs)

    assert len(dialogs) == 6

    dialog = dialogs[0]
    assert isinstance(dialog, lief.PE.ResourceDialogRegular)

    assert dialog.type == lief.PE.ResourceDialog.TYPE.REGULAR
    assert dialog.style == 0x80ca00c0
    assert dialog.extended_style == 0
    assert dialog.x == 0
    assert dialog.y == 0
    assert dialog.cx == 250
    assert dialog.cy == 200
    assert dialog.title == "License"
    assert dialog.font.name == 'MS Shell Dlg'
    assert dialog.font.point_size == 8
    assert dialog.has(lief.PE.ResourceDialog.DIALOG_STYLES.SETFONT)
    assert dialog.has(lief.PE.ResourceDialog.WINDOW_STYLES.POPUP)
    assert not dialog.has(lief.PE.ResourceDialog.WINDOW_STYLES.DISABLED)
    assert dialog.styles_list == [
       lief.PE.ResourceDialog.DIALOG_STYLES.SETFONT,
       lief.PE.ResourceDialog.DIALOG_STYLES.MODALFRAME,
       lief.PE.ResourceDialog.DIALOG_STYLES.SHELLFONT,
    ]

    assert dialog.windows_styles_list == [
        lief.PE.ResourceDialog.WINDOW_STYLES.POPUP,
        lief.PE.ResourceDialog.WINDOW_STYLES.CAPTION,
        lief.PE.ResourceDialog.WINDOW_STYLES.BORDER,
        lief.PE.ResourceDialog.WINDOW_STYLES.DLGFRAME,
        lief.PE.ResourceDialog.WINDOW_STYLES.SYSMENU,
        lief.PE.ResourceDialog.WINDOW_STYLES.GROUP,
    ]

    assert dialog.windows_ext_styles_list == []
    assert dialog.menu is None
    assert dialog.window_class is None

    assert str(dialog) is not None

    items = list(dialog.items)
    assert len(items) == 5

    assert items[0].id == -1
    assert items[0].style == 0x50020000
    assert items[0].extended_style == 0
    assert items[0].x == 7
    assert items[0].y == 4
    assert items[0].cx == 234
    assert items[0].cy == 24
    assert items[0].title == "Please read the following license agreement. Press the PAGE DOWN key to see the rest of the agreement."
    assert items[0].clazz == 130
    assert len(items[0].creation_data) == 0
    assert items[0].window_styles == [
        lief.PE.ResourceDialog.WINDOW_STYLES.CHILD,
        lief.PE.ResourceDialog.WINDOW_STYLES.VISIBLE,
        lief.PE.ResourceDialog.WINDOW_STYLES.GROUP,
    ]
    assert items[0].control_styles == []
    assert items[0].has(lief.PE.ResourceDialog.WINDOW_STYLES.CHILD)
    assert str(items[0]) is not None

    #if is_64bits_platform():
    #    assert lief.hash(dialog) == 17387566843487199836

    assert str(dialog) == dedent("""\
    DIALOG 0, 0, 250, 200
    STYLE: SETFONT | MODALFRAME | SHELLFONT POPUP | CAPTION | BORDER | DLGFRAME | SYSMENU | GROUP
    CAPTION: "License"
    FONT: 8,  MS Shell Dlg
    {
      CONTROL 'Please read the following license agreement. Press the PAGE DOWN key to see the rest of the agreement.', -1, Static,  CHILD | VISIBLE | GROUP, 7, 4, 234, 24
      CONTROL '', 2100, Edit, NORESIZE CHILD | VISIBLE | CAPTION | BORDER | VSCROLL | TABSTOP, 7, 32, 234, 118
      CONTROL 'Do you accept all of the terms of the preceding License Agreement? If you choose No, Install will close. To install you must accept this agreement.', -1, Static,  CHILD | VISIBLE | GROUP, 7, 154, 234, 24
      CONTROL '&Yes', 6, Button,  CHILD | VISIBLE | TABSTOP, 136, 182, 50, 14
      CONTROL '&No', 7, Button,  CHILD | VISIBLE | TABSTOP, 193, 182, 50, 14
    }
    """)

    assert str(dialogs[1]) == dedent("""\
    DIALOG 0, 0, 241, 66
    STYLE: SETFONT | MODALFRAME | SHELLFONT POPUP | CAPTION | BORDER | DLGFRAME | SYSMENU | GROUP
    CAPTION: "Temporary folder"
    FONT: 8,  MS Shell Dlg
    {
      CONTROL 'Please type the location where you want to place the extracted files.', 2108, Static,  CHILD | VISIBLE | GROUP, 7, 4, 234, 22
      CONTROL '', 2101, Edit, VERT | LEFT | RIGHT | NOMOVEX CHILD | VISIBLE | CAPTION | BORDER | TABSTOP, 7, 26, 170, 12
      CONTROL '&Browse...', 2102, Button,  CHILD | VISIBLE | TABSTOP, 184, 25, 50, 14
      CONTROL 'OK', 1, Button,  CHILD | VISIBLE | TABSTOP, 127, 46, 50, 14
      CONTROL 'Cancel', 2, Button,  CHILD | VISIBLE | TABSTOP, 184, 46, 50, 14
    }
    """)

    assert str(dialogs[2]) == dedent("""\
    DIALOG 0, 0, 200, 52
    STYLE: SETFONT | MODALFRAME | SHELLFONT POPUP | CAPTION | BORDER | DLGFRAME | SYSMENU | GROUP
    CAPTION: "Overwrite file"
    FONT: 8,  MS Shell Dlg
    {
      CONTROL 'Do you want to overwrite the file:', -1, Static,  CHILD | VISIBLE | GROUP, 7, 4, 193, 8
      CONTROL '', 2104, Static,  CHILD | VISIBLE | GROUP, 7, 14, 193, 16
      CONTROL '&Yes', 6, Button,  CHILD | VISIBLE | TABSTOP, 7, 34, 50, 14
      CONTROL 'Yes To &All', 2105, Button,  CHILD | VISIBLE | TABSTOP, 64, 34, 50, 14
      CONTROL '&No', 7, Button,  CHILD | VISIBLE | TABSTOP, 121, 34, 50, 14
    }
    """)

    assert str(dialogs[3]) == dedent("""\
    DIALOG 0, 0, 250, 84
    STYLE: SETFONT | MODALFRAME | SHELLFONT POPUP | CAPTION | BORDER | DLGFRAME | SYSMENU | GROUP
    CAPTION: "Extract"
    FONT: 8,  MS Shell Dlg
    {
      CONTROL '&Cancel', 2, Button,  CHILD | VISIBLE | TABSTOP, 192, 62, 50, 14
      CONTROL 'Extracting', 2113, Static,  CHILD | GROUP, 7, 48, 235, 8
      CONTROL '', 2103, Static,  CHILD | VISIBLE | GROUP, 45, 48, 235, 8
      CONTROL 'Initializing... Please wait...', 2114, Static,  CHILD | VISIBLE | GROUP, 7, 48, 235, 8
      CONTROL 'Generic1', 2106, msctls_progress32,  CHILD | VISIBLE, 7, 62, 176, 8
      CONTROL 'User1', 2107, SysAnimate32, TOP | NOMOVEY | BOTTOM | LEFT | RIGHT | NOMOVEX CHILD | VISIBLE | TABSTOP, 7, 7, 184, 36
    }
    """)

    assert str(dialogs[4]) == dedent("""\
    DIALOG 0, 0, 250, 84
    STYLE: SETFONT | MODALFRAME | SHELLFONT POPUP | CAPTION | BORDER | DLGFRAME | SYSMENU | GROUP
    CAPTION: "Extract"
    FONT: 8,  MS Shell Dlg
    {
      CONTROL '&Cancel', 2, Button,  CHILD | VISIBLE | TABSTOP, 192, 62, 50, 14
      CONTROL 'Extracting', 2113, Static,  CHILD | GROUP, 7, 48, 235, 8
      CONTROL '', 2103, Static,  CHILD | VISIBLE | GROUP, 45, 48, 235, 8
      CONTROL 'Initializing... Please wait...', 2114, Static,  CHILD | VISIBLE | GROUP, 7, 48, 235, 8
    }
    """)

    assert str(dialogs[5]) == dedent("""\
    DIALOG 0, 0, 186, 95
    STYLE: SETFONT | MODALFRAME | SHELLFONT POPUP | CAPTION | BORDER | DLGFRAME | SYSMENU
    CAPTION: "Warning"
    FONT: 8,  MS Shell Dlg
    {
      CONTROL 'E&xit', 2110, Button,  CHILD | VISIBLE | TABSTOP, 129, 76, 50, 14
      CONTROL '&Continue', 2109, Button, TOP | BOTTOM | LEFT | RIGHT CHILD | VISIBLE | TABSTOP, 73, 76, 50, 14
      CONTROL '', 2111, Static,  CHILD | VISIBLE | GROUP, 12, 12, 163, 29
      CONTROL 'Do you want to continue?', -1, Static,  CHILD | VISIBLE | GROUP, 12, 52, 82, 8
    }
    """)

def test_resource_dialogs_extended():
    input_path = Path(get_sample("PE/PE64_x86-64_binary_mfc-application.exe"))

    pe = lief.PE.parse(input_path)

    manager = pe.resources_manager
    assert isinstance(manager, lief.PE.ResourcesManager)

    dialogs = manager.dialogs
    assert len(dialogs) == 1

    dialog = dialogs[0]
    assert isinstance(dialog, lief.PE.ResourceDialogExtended)

    assert dialog.font.point_size == 8
    assert dialog.font.typeface == "MS Shell Dlg"

    assert dialog.type == lief.PE.ResourceDialog.TYPE.EXTENDED
    assert dialog.help_id == 0
    assert dialog.style == 0x80c800c8
    assert dialog.extended_style == 0
    assert dialog.x == 0
    assert dialog.y == 0
    assert dialog.cx == 170
    assert dialog.cy == 62
    assert dialog.title == "À propos de Hello"
    assert dialog.font.typeface == 'MS Shell Dlg'
    assert dialog.font.point_size == 8
    assert dialog.has(lief.PE.ResourceDialog.DIALOG_STYLES.SETFONT)
    assert dialog.has(lief.PE.ResourceDialog.WINDOW_STYLES.POPUP)
    assert not dialog.has(lief.PE.ResourceDialog.WINDOW_STYLES.DISABLED)
    assert dialog.styles_list == [
       lief.PE.ResourceDialog.DIALOG_STYLES.SETFONT,
       lief.PE.ResourceDialog.DIALOG_STYLES.MODALFRAME,
       lief.PE.ResourceDialog.DIALOG_STYLES.FIXEDSYS,
       lief.PE.ResourceDialog.DIALOG_STYLES.SHELLFONT,
    ]

    assert dialog.windows_styles_list == [
        lief.PE.ResourceDialog.WINDOW_STYLES.POPUP,
        lief.PE.ResourceDialog.WINDOW_STYLES.CAPTION,
        lief.PE.ResourceDialog.WINDOW_STYLES.BORDER,
        lief.PE.ResourceDialog.WINDOW_STYLES.DLGFRAME,
        lief.PE.ResourceDialog.WINDOW_STYLES.SYSMENU,
    ]

    assert dialog.windows_ext_styles_list == []
    assert dialog.menu is None
    assert dialog.window_class is None

    items = list(dialog.items)
    assert len(items) == 4

    assert items[0].id == -1
    assert items[0].style == 0x50000003
    assert items[0].extended_style == 0
    assert items[0].x == 14
    assert items[0].y == 14
    assert items[0].cx == 21
    assert items[0].cy == 20
    assert items[0].title == 128
    assert items[0].clazz == 130
    assert len(items[0].creation_data) == 0
    assert items[0].window_styles == [
        lief.PE.ResourceDialog.WINDOW_STYLES.CHILD,
        lief.PE.ResourceDialog.WINDOW_STYLES.VISIBLE,
    ]
    assert items[0].control_styles == [
        lief.PE.ResourceDialog.CONTROL_STYLES.TOP,
        lief.PE.ResourceDialog.CONTROL_STYLES.NOMOVEY,
        lief.PE.ResourceDialog.CONTROL_STYLES.BOTTOM,
        lief.PE.ResourceDialog.CONTROL_STYLES.LEFT,
        lief.PE.ResourceDialog.CONTROL_STYLES.RIGHT,
        lief.PE.ResourceDialog.CONTROL_STYLES.NOMOVEX,
    ]
    assert items[0].has(lief.PE.ResourceDialog.WINDOW_STYLES.CHILD)
    assert str(items[0]) is not None

    #if is_64bits_platform():
    #    assert lief.hash(dialog) == 13416642428894329102

    assert str(dialogs[0]) == dedent("""\
    DIALOGEX 0, 0, 170, 62
    STYLE: SETFONT | MODALFRAME | FIXEDSYS | SHELLFONT POPUP | CAPTION | BORDER | DLGFRAME | SYSMENU
    CAPTION: "À propos de Hello"
    FONT: 8, MS Shell Dlg
    {
      CONTROL 'ord=128', -1, Static, TOP | NOMOVEY | BOTTOM | LEFT | RIGHT | NOMOVEX CHILD | VISIBLE, 14, 14, 21, 20
      CONTROL 'Hello, version 1.0', -1, Static, VERT | LEFT | RIGHT | NOMOVEX CHILD | VISIBLE | GROUP, 42, 14, 114, 8
      CONTROL 'Copyright (C) 2016', -1, Static,  CHILD | VISIBLE | GROUP, 42, 26, 114, 8
      CONTROL 'OK', 1, Button, TOP | BOTTOM | LEFT | RIGHT CHILD | VISIBLE | GROUP | TABSTOP, 113, 41, 50, 14
    }
    """)

def test_mfc_resource_builder():
    sample_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')

    mfc = lief.PE.parse(sample_path)
    new = lief.PE.parse(list(mfc.write_to_bytes()))
    assert mfc.resources == new.resources

def test_notepadpp_resource_builder(tmp_path):
    sample_file = get_sample('PE/PE32_x86_binary_Notepad++.zip')
    sample_dir  = tmp_path / "Notepad++"

    sample = sample_dir / "notepad++.exe"

    with zipfile.ZipFile(sample_file, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)

    notepadpp = lief.PE.parse(sample.as_posix())

    new = lief.PE.parse(list(notepadpp.write_to_bytes()))

    assert new.resources == notepadpp.resources

def test_filezilla_resource_builder(tmp_path):
    sample_file = get_sample('PE/PE64_x86-64_binary_FileZilla.zip')
    sample_dir  = tmp_path / "FileZilla"

    sample = sample_dir / "filezilla.exe"

    with zipfile.ZipFile(sample_file, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)

    filezilla = lief.PE.parse(sample.as_posix())
    new = lief.PE.parse(list(filezilla.write_to_bytes()))

    assert filezilla.resources == new.resources

def test_resource_directory_add_directory_node(tmp_path):
    sample_file = get_sample('PE/PE32_x86_binary_Notepad++.zip')
    sample_dir  = tmp_path / "Notepad++"

    sample = sample_dir / "notepad++.exe"

    with zipfile.ZipFile(sample_file, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)

    for seed in (5, 20, 99):
        app = lief.PE.parse(sample.as_posix())
        assert [child.id for child in app.resources.childs] == [1, 2, 3, 4, 5, 6, 12, 14, 16, 24]
        nodes = []

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.HTML.value
        nodes.append(node)

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.RCDATA.value
        nodes.append(node)

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.FONT.value
        nodes.append(node)

        # Deterministically shuffle the add order with the seed
        random.Random(seed).shuffle(nodes)

        for node in nodes:
            new_node = app.resources.add_child(node)
            assert isinstance(new_node, lief.PE.ResourceNode)

        # Should be in sorted order by ID
        assert [child.id for child in app.resources.childs] == [1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 23, 24]

    for seed in (7, 23, 91):
        app = lief.PE.parse(sample.as_posix())
        assert lief.PE.ResourcesManager.TYPE.RCDATA.value not in [child.id for child in app.resources.childs]

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.RCDATA.value
        rcdata_node = app.resources.add_child(node)
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
            new_node = rcdata_node.add_child(node)
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
        app = lief.PE.parse(sample)
        assert lief.PE.ResourcesManager.TYPE.RCDATA.value not in [child.id for child in app.resources.childs]

        node = lief.PE.ResourceDirectory()
        node.id = lief.PE.ResourcesManager.TYPE.RCDATA.value
        rcdata_node = app.resources.add_child(node)
        assert isinstance(rcdata_node, lief.PE.ResourceNode)

        node = lief.PE.ResourceDirectory()
        node.id = 10
        lang_node = rcdata_node.add_child(node)

        assert len(lang_node.childs) == 0
        nodes = []

        for id_ in (1033, 44, 500, 0):
            node = lief.PE.ResourceData()
            node.id = id_
            nodes.append(node)

        # Deterministically shuffle the add order with the seed
        random.Random(seed).shuffle(nodes)

        for node in nodes:
            new_node = lang_node.add_child(node)
            assert isinstance(new_node, lief.PE.ResourceNode)

        # Should be in sorted order
        assert [child.name or child.id for child in lang_node.childs] == [0, 44, 500, 1033]

def test_nodes(tmp_path):
    sample_path = get_sample('PE/PE64_x86-64_binary_mfc-application.exe')

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

def test_add_node(tmp_path: Path):
    target_input = Path(get_sample("PE/pe_reader.exe"))
    pe = lief.PE.parse(target_input)

    root = pe.resources
    assert len(root.childs) == 1

    dir_node = lief.PE.ResourceDirectory()
    dir_node.id = lief.PE.ResourcesManager.TYPE.HTML.value

    data_node = lief.PE.ResourceData()
    data_node.content = b"Hello World"
    dir_node.add_child(data_node)
    root.add_child(dir_node)

    output = tmp_path / "pe_reader.exe"
    pe.write(output.as_posix())

    new = lief.PE.parse(output)
    checked, err = lief.PE.check_layout(new)
    assert checked, err

    children = new.resources.childs
    assert len(children) == 2

    assert children[0].id == lief.PE.ResourcesManager.TYPE.HTML.value
    assert bytes(children[0].childs[0].content) == b"Hello World"

    if is_windows() and is_x86_64():
        ret = win_exec(output, gui=False, args=[output.as_posix(), ])
        assert ret is not None

        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0


def test_transfer_resources(tmp_path: Path):
    target_input = Path(get_sample("PE/pe_reader.exe"))
    avast = lief.PE.parse(get_sample("PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe"))

    rsrc_dir = avast.data_directory(lief.PE.DataDirectory.TYPES.RESOURCE_TABLE)
    rsrc_raw = bytes(rsrc_dir.content)

    new_tree = lief.PE.ResourceNode.parse(rsrc_raw, rsrc_dir.rva)
    assert new_tree is not None

    pe_reader = lief.PE.parse(target_input)
    assert len(pe_reader.resources.childs) == 1

    pe_reader.set_resources(new_tree)
    assert len(pe_reader.resources.childs) == 7

    output = tmp_path / target_input.name
    pe_reader.write(output.as_posix())

    new_pe_reader = lief.PE.parse(output)

    manager = new_pe_reader.resources_manager
    assert len(manager.icons) == 3
    assert len(manager.manifest) > 0

    if is_windows() and is_x86_64():
        ret = win_exec(output, gui=False, universal_newlines=False,
                       args=[output.as_posix(), ])
        assert ret is not None

        retcode, stdout = ret
        assert retcode == 0
        assert len(stdout) > 0

def test_add_manifest(tmp_path: Path):
    root = lief.PE.ResourceDirectory()
    manager = lief.PE.ResourcesManager(root)
    manager.manifest = """
    <?xml version='1.0' encoding='UTF-8' standalone='yes'?>
    <assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>
      <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
          <requestedPrivileges>
            <requestedExecutionLevel level='asInvoker' uiAccess='false' />
          </requestedPrivileges>
        </security>
      </trustInfo>
    </assembly>
    """
    assert len(root.childs) == 1
    assert len(root.childs[0].childs) == 1
    assert len(root.childs[0].childs[0].childs) == 1
    assert len(root.childs[0].childs[0].childs[0].content) == 416

def test_add_icon(tmp_path: Path):
    # Icon from VirtualBox-7.1.0-164728-Win.exe (16x16)
    RAW_ICON = """
    00:00:01:00:01:00:10:10:00:00:01:00:20:00:68:04:00:00:16:00:00:00:28:00:00:00
    10:00:00:00:20:00:00:00:01:00:20:00:00:00:00:00:00:04:00:00:13:0b:00:00:13:0b
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:8a:75:00:00
    8a:75:00:03:8a:75:00:0b:8a:75:00:0c:8a:75:00:0c:8a:75:00:04:8b:75:00:00:8a:75
    00:09:8a:75:00:0c:8a:75:00:0c:8a:75:00:0c:8a:75:00:06:8c:76:00:00:00:00:00:00
    00:00:00:00:8a:75:00:00:8a:75:00:15:8a:75:00:8b:8a:75:00:c1:8a:75:00:c2:8a:75
    00:c2:8a:75:00:59:8a:75:00:00:8a:75:00:72:8a:75:00:c5:8a:75:00:c2:8a:75:00:c2
    8a:75:00:ad:8a:75:00:48:00:00:00:00:8a:75:00:00:8a:75:00:00:8a:75:00:76:8a:75
    00:ff:8a:75:00:f2:8a:75:00:ef:8a:75:00:ff:8a:75:00:aa:8b:76:00:01:8a:75:00:5e
    8a:75:00:eb:8a:75:00:eb:8a:75:00:ed:8a:75:00:fc:8a:75:00:e0:00:00:00:00:8a:75
    00:00:8a:75:00:09:8a:75:00:bb:8a:75:00:f5:8a:75:00:53:8a:75:00:39:8a:75:00:de
    8a:75:00:df:8a:75:00:1e:8a:75:00:09:8a:75:00:26:8a:75:00:26:8a:75:00:35:8a:75
    00:d5:8a:75:00:ff:00:00:00:00:8a:75:00:00:8a:75:00:29:8a:75:00:e9:8a:75:00:ce
    8a:75:00:12:8a:75:00:02:8a:75:00:a6:8a:75:00:fd:8a:75:00:50:8a:75:00:00:8b:75
    00:00:8a:75:00:00:8a:75:00:10:8a:75:00:cd:8a:75:00:ff:8a:75:00:00:8a:75:00:00
    8a:75:00:5e:8a:75:00:ff:8a:75:00:96:89:73:00:00:8a:75:00:00:8a:75:00:66:8a:75
    00:ff:8a:75:00:b3:8a:75:00:68:8a:75:00:6a:8a:75:00:69:8a:75:00:73:8a:75:00:e2
    8a:75:00:ff:8a:75:00:00:8a:75:00:01:8a:75:00:9c:8a:75:00:ff:8a:75:00:58:8a:75
    00:00:8a:75:00:00:8a:75:00:2f:8a:75:00:ea:8a:75:00:ff:8a:75:00:ff:8a:75:00:ff
    8a:75:00:ff:8a:75:00:ff:8a:75:00:ff:8a:75:00:ff:8a:75:00:00:8a:75:00:16:8a:75
    00:d3:8a:75:00:e5:8a:75:00:25:8a:75:00:00:8a:75:00:00:8a:75:00:09:8a:75:00:64
    8a:75:00:7b:8a:75:00:79:8a:75:00:79:8a:75:00:79:8a:75:00:79:8a:75:00:79:8a:75
    00:79:8a:75:00:00:8a:75:00:40:8a:75:00:f8:8a:75:00:b5:8a:75:00:07:8a:75:00:00
    8a:75:00:01:8a:75:00:01:00:ff:ff:00:00:f8:ff:00:00:f8:ff:00:00:00:00:00:00:00
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:8a:75:00:00:8a:75:00:7b:8a:75:00:ff
    8a:75:00:77:8a:75:00:00:8a:75:00:67:8a:75:00:a3:8f:74:00:32:07:93:ff:21:11:91
    f2:9a:11:91:f2:a3:11:91:f2:a3:11:91:f2:a3:11:91:f2:a3:11:91:f2:a2:11:91:f2:a2
    8a:75:00:0a:8a:75:00:b7:8a:75:00:f6:8a:75:00:3c:8a:75:00:0e:8a:75:00:cc:8a:75
    00:ec:8f:74:00:2b:02:94:ff:17:11:91:f2:d6:11:91:f2:ff:11:91:f2:fc:11:91:f2:fb
    11:91:f2:fc:11:91:f2:fe:11:91:f2:ff:8a:75:00:2d:8a:75:00:e6:8a:75:00:d0:8a:75
    00:10:8a:75:00:38:8a:75:00:f4:8a:75:00:bd:8c:75:00:0a:00:a6:ff:01:11:91:f2:9f
    11:91:f2:ff:11:91:f2:89:11:91:f2:3c:11:91:f2:4c:11:91:f2:d9:11:91:f2:ff:8a:75
    00:68:8a:75:00:fe:8a:75:00:ab:8a:75:00:20:8a:75:00:80:8a:75:00:ff:8a:75:00:80
    8a:75:00:00:12:91:f0:00:11:91:f2:5f:11:91:f2:ff:11:91:f2:9c:11:91:f2:1d:11:91
    f2:2c:11:91:f2:d3:11:91:f2:ff:8a:75:00:b0:8a:75:00:ff:8a:75:00:f3:8a:75:00:e7
    8a:75:00:f5:8a:75:00:f6:8a:75:00:44:8a:75:00:00:11:91:f2:00:11:91:f2:29:11:91
    f2:e6:11:91:f2:f9:11:91:f2:e7:11:91:f2:e9:11:91:f2:fb:11:91:f2:e2:8a:75:00:b3
    8a:75:00:c7:8a:75:00:c7:8a:75:00:c8:8a:75:00:c9:8a:75:00:ab:8a:75:00:16:8a:75
    00:00:11:91:f2:00:11:91:f2:09:11:91:f2:96:11:91:f2:c9:11:91:f2:c8:11:91:f2:c8
    11:91:f2:b3:11:91:f2:4c:8a:75:00:0f:8a:75:00:0f:8a:75:00:0f:8a:75:00:0f:8a:75
    00:0f:8a:75:00:0c:8a:75:00:01:8a:75:00:00:11:91:f2:00:11:91:f2:00:11:91:f2:0a
    11:91:f2:0f:11:91:f2:0f:11:91:f2:0f:11:91:f2:08:11:91:f2:00:f0:00:00:00:e0:40
    00:00:e0:00:00:00:c0:00:00:00:c0:38:00:00:c6:00:00:00:86:00:00:00:86:00:00:00
    84:3f:00:00:88:00:00:00:00:00:00:00:00:00:00:00:01:80:00:00:01:80:00:00:01:80
    00:00:01:80:00:00
    """
    target_input = Path(get_sample("PE/pe_reader.exe"))
    pe = lief.PE.parse(target_input)
    manager = pe.resources_manager
    raw_icon = bytes.fromhex(RAW_ICON.replace('\n', '').replace(':', '').strip())
    new_icon = lief.PE.ResourceIcon.from_serialization(raw_icon)
    lief.logging.enable_debug()
    manager.add_icon(new_icon)
    print(pe.resources)
    out = tmp_path / target_input.name
    pe.write(out.as_posix())

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_driver_rsrc():
    input_file = Path(get_sample("private/PE/vgk.sys"))
    pe = lief.PE.parse(input_file)

    manager = pe.resources_manager
    assert isinstance(manager, lief.PE.ResourcesManager)

    version = manager.version[0]
    assert version.file_info.signature == 0xfeef04bd
    assert version.file_info.struct_version == 0x10000
    assert version.file_info.file_version_ms == 65552
    assert version.file_info.file_version_ls == 1048583
    assert version.file_info.product_version_ms == 65552
    assert version.file_info.product_version_ls == 1048583
    assert version.file_info.file_flags_mask == 63
    assert version.file_info.file_flags == 0
    assert version.file_info.file_os == 262148
    assert version.file_info.file_os == lief.PE.ResourceVersion.fixed_file_info_t.VERSION_OS.NT_WINDOWS32.value
    assert version.file_info.file_type == 3581946624
    assert version.file_info.file_subtype == 0
    assert version.file_info.file_date_ms == 0
    assert version.file_info.file_date_ls == 0
