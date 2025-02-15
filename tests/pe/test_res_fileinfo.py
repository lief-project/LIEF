import lief
import utils

#lief.logging.set_level(lief.logging.LEVEL.DEBUG)

def test_issue_686():
    """
    https://github.com/lief-project/LIEF/issues/686
    """
    path = utils.get_sample("PE/res/bdfa7195fc318cb4f232c63479fd904887e2989a8bbd57aab9eeb57210a7471a.neut")
    pe = lief.PE.parse(path)

    assert pe is not None

    versions = pe.resources_manager.version
    assert len(versions) == 1
    assert len(versions[0].string_file_info.children) == 1
    table = versions[0].string_file_info.children[0]
    entries = table.entries
    assert len(entries) == 8

    assert table["OriginalFilename"] == "d7x.exe"
    assert table["InternalName"]     == "d7x"
    assert table["ProductVersion"]   == "21.09.2402"
    assert table["FileVersion"]      == "21.09.2402"
    assert table["ProductName"]      == "d7x"
    assert table["LegalCopyright"]   == "d7xTech (formerly Foolish IT)"
    assert table["FileDescription"]  == "d7x (PC Repair Multi-Tool)"
    assert table["CompanyName"]      == "d7xTech (formerly Foolish IT)"

def test_issue_687():
    """
    https://github.com/lief-project/LIEF/issues/687
    """
    path = utils.get_sample("PE/res/9b58db32f6224e213cfd130d6cd7a18b2440332bfd99e0aef4313de8099fa955.neut")
    pe = lief.PE.parse(path)

    assert pe is not None

    dialogs = pe.resources_manager.dialogs
    assert len(dialogs) == 15

    assert dialogs[0].title == "About Phone Dialer"
    assert [d.title for d in dialogs[0].items] == [
            '&More Information', 'OK', 'Phone Dialer 1.50',
            'Developed for Microsoft by Active Voice.  (C)1998 Active Voice Corporation.\nAll rights reserved.',
            None, 'Active Voice offers a full range of messaging and communications software designed for Microsoft Windows(R) and BackOffice(tm).',
            'For more information, a free upgrade to the latest version of this program, or other software, visit: http://www.activevoice.com/dialer', None]

    assert dialogs[1].title == "Add ILS Server"
    assert [d.title for d in dialogs[1].items] == ['&Server Address', None, 'OK', 'Cancel']

    assert dialogs[3].title == "Video"
    assert [d.title for d in dialogs[3].items] == [None]

    assert dialogs[6].title == "More Speed Dial Entries"
    assert [d.title for d in dialogs[6].items] == [118, 'Select Entry to Dial', 'List1', 'Place &Call', '&Edit...', 'Cancel']

    assert dialogs[7].title == "Edit Speed Dial List"
    assert [d.title for d in dialogs[7].items] == ['Entrie&s', 'List1', '&OK', '&Cancel', 'Move &Up', 'Move &Down', '&Add...', '&Edit...', '&Remove']

    assert dialogs[8].title == "Speed Dial"
    assert [d.title for d in dialogs[8].items] == [118, 'Enter a display name and a phone number or network address', '&Display name:', None, '&Number or address:', None, 'Dial as', '&Phone call', 'Int&ernet call', 'Internet &conference', 'OK', 'Cancel']

    assert dialogs[9].title == ""
    assert [d.title for d in dialogs[9].items] == []

    assert dialogs[10].title == "Take Picture"
    assert [d.title for d in dialogs[10].items] == ['&Video Device', None, '&Format...', '&Source...', '&Display...', '&Take Picture', 'Preview']

    assert dialogs[12].title == "Add User"
    assert [d.title for d in dialogs[12].items] == ['Enter the name of the user to add.  You must search the network directory to verify that the user exists.', '&User:', None, '&Search', 'Search &Results:', None, '&Add', '&Cancel', None]


def test_issue_689():
    """
    https://github.com/lief-project/LIEF/issues/689
    """
    path = utils.get_sample("PE/res/07e7d2848b6f9f626e9c7dc06de13c3d1f31ab31ce55226931d6e4d426178be6.neut")
    pe = lief.PE.parse(path)

    assert pe is not None

    versions = pe.resources_manager.version
    assert len(versions) == 1
    assert len(versions[0].string_file_info.children) == 1
    table = versions[0].string_file_info.children[0]
    entries = table.entries
    assert len(entries) == 12

    assert table["__NONE__"] is None
    assert table["SpecialBuild"]     == ""
    assert table["ProductVersion"]   == "1, 0, 0, 0"
    assert table["PrivateBuild"]     == ""
    assert table["OriginalFilename"] == "DSignTool"
    assert table["ProductName"].encode('utf8') == b"\xe6\x95\xb0\xe5\xad\x97\xe7\xad\xbe\xe5\x90\x8d\xe5\xb7\xa5\xe5\x85\xb7(\xe5\x91\xbd\xe4\xbb\xa4\xe8\xa1\x8c)"
    assert table["LegalTrademarks"]  == ""
    assert table["InternalName"]     == "CSignTool"
    assert table["FileVersion"]      == "1, 9, 0, 0"
    assert table["LegalCopyright"]   == "Copyright ? 2012"
    assert table["FileDescription"].encode('utf8') == b"\xe6\x95\xb0\xe5\xad\x97\xe7\xad\xbe\xe5\x90\x8d\xe5\xb7\xa5\xe5\x85\xb7(\xe5\x91\xbd\xe4\xbb\xa4\xe8\xa1\x8c)"
    assert table["CompanyName"].encode('utf8') == b"\xe4\xb8\x8a\xe6\xb5\xb7\xe5\x9f\x9f\xe8\x81\x94\xe8\xbd\xaf\xe4\xbb\xb6\xe6\x8a\x80\xe6\x9c\xaf\xe6\x9c\x89\xe9\x99\x90\xe5\x85\xac\xe5\x8f\xb8"
    assert table["Comments"]         == ""

def test_issue_691():
    """
    https://github.com/lief-project/LIEF/issues/691
    """
    path = utils.get_sample("PE/res/1dc4c94163a436c401d163e317e5bdbb55a84600a63ad11805c892d4ad1e5be3.neut")
    pe = lief.PE.parse(path)

    versions = pe.resources_manager.version
    assert len(versions) == 1
    assert len(versions[0].string_file_info.children) == 1
    table = versions[0].string_file_info.children[0]
    entries = table.entries
    assert len(entries) == 6

    assert table["LegalTrademarks"]   == "Microsoft Firewall"
    assert table["LegalCopyright"]    == "Microsoft"
    assert table["FileDescription"]   == "Microsoft Firewall"
    assert table["CompanyName"]       == "Xiang Corporation"
    assert table["Comments"]          == "Microsoft Firewall"
    key = b"Produc\xe5\xa9\x8d\xc2\x90\x03".decode("utf8")
    assert table[key] == ""

def test_issue_693():
    """
    https://github.com/lief-project/LIEF/issues/693
    """
    path = utils.get_sample("PE/res/4bfaa99393f635cd05d91a64de73edb5639412c129e049f0fe34f88517a10fc6.neut")
    pe = lief.PE.parse(path)

    assert pe is not None

    versions = pe.resources_manager.version
    assert len(versions) == 1
    assert len(versions[0].string_file_info.children) == 1
    table = versions[0].string_file_info.children[0]
    entries = table.entries
    assert len(entries) == 10

    assert table["LegalTrademarks"]   == ""
    assert table["Build Description"] == ""

    path = utils.get_sample("PE/res/731bb363a01f45b64c0065e1cdfe8cc653930f102f715bc5073ac77c1d4bae2a.neut")
    pe = lief.PE.parse(path)

    assert pe is not None

    versions = pe.resources_manager.version
    assert len(versions) == 1
    assert len(versions[0].string_file_info.children) == 1
    table = versions[0].string_file_info.children[0]
    entries = table.entries
    assert len(entries) == 11

    assert table["Comments"] == ""
