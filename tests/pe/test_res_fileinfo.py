import lief
import utils

lief.logging.set_level(lief.logging.LEVEL.DEBUG)

def test_issue_686():
    """
    https://github.com/lief-project/LIEF/issues/686
    """
    path = utils.get_sample("PE/res/bdfa7195fc318cb4f232c63479fd904887e2989a8bbd57aab9eeb57210a7471a.neut")
    pe = lief.parse(path)

    assert pe is not None

    file_info = pe.resources_manager.version.string_file_info
    assert len(file_info.langcode_items) == 1
    item = file_info.langcode_items[0]

    assert len(item.items) == 8
    assert item.items["OriginalFilename"] == b"d7x.exe"
    assert item.items["InternalName"]     == b"d7x"
    assert item.items["ProductVersion"]   == b"21.09.2402"
    assert item.items["FileVersion"]      == b"21.09.2402"
    assert item.items["ProductName"]      == b"d7x"
    assert item.items["LegalCopyright"]   == b"d7xTech (formerly Foolish IT)"
    assert item.items["FileDescription"]  == b"d7x (PC Repair Multi-Tool)"
    assert item.items["CompanyName"]      == b"d7xTech (formerly Foolish IT)"

def test_issue_687():
    """
    https://github.com/lief-project/LIEF/issues/687
    """
    path = utils.get_sample("PE/res/9b58db32f6224e213cfd130d6cd7a18b2440332bfd99e0aef4313de8099fa955.neut")
    pe = lief.parse(path)

    assert pe is not None

    dialogs = pe.resources_manager.dialogs
    assert len(dialogs) == 9

    assert dialogs[0].title == "About Phone Dialer"
    assert [d.title for d in dialogs[0].items] == [
            '&More Information', 'OK', 'Phone Dialer 1.50',
            'Developed for Microsoft by Active Voice.  (C)1998 Active Voice Corporation.\nAll rights reserved.',
            '', 'Active Voice offers a full range of messaging and communications software designed for Microsoft Windows(R) and BackOffice(tm).',
            'For more information, a free upgrade to the latest version of this program, or other software, visit: http://www.activevoice.com/dialer', '']

    assert dialogs[1].title == "Add ILS Server"
    assert [d.title for d in dialogs[1].items] == ['&Server Address', '', 'OK', 'Cancel']

    assert dialogs[2].title == "Video"
    assert [d.title for d in dialogs[2].items] == ['']

    assert dialogs[3].title == "More Speed Dial Entries"
    assert [d.title for d in dialogs[3].items] == ['', 'Select Entry to Dial', 'List1', 'Place &Call', '&Edit...', 'Cancel']

    assert dialogs[4].title == "Edit Speed Dial List"
    assert [d.title for d in dialogs[4].items] == ['Entrie&s', 'List1', '&OK', '&Cancel', 'Move &Up', 'Move &Down', '&Add...', '&Edit...', '&Remove']

    assert dialogs[5].title == "Speed Dial"
    assert [d.title for d in dialogs[5].items] == ['', 'Enter a display name and a phone number or network address', '&Display name:', '', '&Number or address:', '', 'Dial as', '&Phone call', 'Int&ernet call', 'Internet &conference', 'OK', 'Cancel']

    assert dialogs[6].title == ""
    assert [d.title for d in dialogs[6].items] == []

    assert dialogs[7].title == "Take Picture"
    assert [d.title for d in dialogs[7].items] == ['&Video Device', '', '&Format...', '&Source...', '&Display...', '&Take Picture', 'Preview']

    assert dialogs[8].title == "Add User"
    assert [d.title for d in dialogs[8].items] == ['Enter the name of the user to add.  You must search the network directory to verify that the user exists.', '&User:', '', '&Search', 'Search &Results:', '', '&Add', '&Cancel', '']


def test_issue_689():
    """
    https://github.com/lief-project/LIEF/issues/689
    """
    path = utils.get_sample("PE/res/07e7d2848b6f9f626e9c7dc06de13c3d1f31ab31ce55226931d6e4d426178be6.neut")
    pe = lief.parse(path)

    assert pe is not None

    file_info = pe.resources_manager.version.string_file_info
    assert len(file_info.langcode_items) == 1
    item = file_info.langcode_items[0]

    assert len(item.items) == 12

    assert item.items["SpecialBuild"]     == b""
    assert item.items["ProductVersion"]   == b"1, 0, 0, 0"
    assert item.items["PrivateBuild"]     == b""
    assert item.items["OriginalFilename"] == b"DSignTool"
    assert item.items["ProductName"]      == b"\xe6\x95\xb0\xe5\xad\x97\xe7\xad\xbe\xe5\x90\x8d\xe5\xb7\xa5\xe5\x85\xb7(\xe5\x91\xbd\xe4\xbb\xa4\xe8\xa1\x8c)"
    assert item.items["LegalTrademarks"]  == b""
    assert item.items["InternalName"]     == b"CSignTool"
    assert item.items["FileVersion"]      == b"1, 9, 0, 0"
    assert item.items["LegalCopyright"]   == b"Copyright ? 2012"
    assert item.items["FileDescription"]  == b"\xe6\x95\xb0\xe5\xad\x97\xe7\xad\xbe\xe5\x90\x8d\xe5\xb7\xa5\xe5\x85\xb7(\xe5\x91\xbd\xe4\xbb\xa4\xe8\xa1\x8c)"
    assert item.items["CompanyName"]      == b"\xe4\xb8\x8a\xe6\xb5\xb7\xe5\x9f\x9f\xe8\x81\x94\xe8\xbd\xaf\xe4\xbb\xb6\xe6\x8a\x80\xe6\x9c\xaf\xe6\x9c\x89\xe9\x99\x90\xe5\x85\xac\xe5\x8f\xb8"
    assert item.items["Comments"]         == b""

def test_issue_691():
    """
    https://github.com/lief-project/LIEF/issues/691
    """
    path = utils.get_sample("PE/res/1dc4c94163a436c401d163e317e5bdbb55a84600a63ad11805c892d4ad1e5be3.neut")
    pe = lief.parse(path)

    assert pe is not None

    file_info = pe.resources_manager.version.string_file_info
    assert len(file_info.langcode_items) == 1
    item = file_info.langcode_items[0]

    assert len(item.items) == 6

    assert item.items["LegalTrademarks"]   == b"Microsoft Firewall"
    assert item.items["LegalCopyright"]    == b"Microsoft"
    assert item.items["FileDescription"]   == b"Microsoft Firewall"
    assert item.items["CompanyName"]       == b"Xiang Corporation"
    assert item.items["Comments"]          == b"Microsoft Firewall"
    key = b"Produc\xe5\xa9\x8d\xc2\x90\x03".decode("utf8")
    assert item.items[key]  == b""

def test_issue_693():
    """
    https://github.com/lief-project/LIEF/issues/693
    """
    path = utils.get_sample("PE/res/4bfaa99393f635cd05d91a64de73edb5639412c129e049f0fe34f88517a10fc6.neut")
    pe = lief.parse(path)

    assert pe is not None

    file_info = pe.resources_manager.version.string_file_info
    assert len(file_info.langcode_items) == 1
    item = file_info.langcode_items[0]

    assert len(item.items) == 10

    assert item.items["LegalTrademarks"]   == b""
    assert item.items["Build Description"] == b""


    path = utils.get_sample("PE/res/731bb363a01f45b64c0065e1cdfe8cc653930f102f715bc5073ac77c1d4bae2a.neut")
    pe = lief.parse(path)

    assert pe is not None

    file_info = pe.resources_manager.version.string_file_info
    assert len(file_info.langcode_items) == 1
    item = file_info.langcode_items[0]

    assert len(item.items) == 11

    assert item.items["Comments"] == b""
