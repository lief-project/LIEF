#!/usr/bin/env python2
#-*- coding: utf-8 -*-

# This file is used to generate config file for LIEF test
# It use `pefile`(https://github.com/erocarrera/pefile) to generate yaml config file

import re
import yaml
import hashlib
import pefile
import sys
import os
import copy

def generate_node_config(node):
    node_y = dict()
    node_y["childs"] = []
    if type(node) == pefile.ResourceDirData:
        node_y["type"] = 0
        node_y["Characteristics"]      = node.struct.Characteristics
        node_y["TimeDateStamp"]        = node.struct.TimeDateStamp
        node_y["MajorVersion"]         = node.struct.MajorVersion
        node_y["MinorVersion"]         = node.struct.MinorVersion
        node_y["NumberOfNamedEntries"] = node.struct.NumberOfNamedEntries
        node_y["NumberOfIdEntries"]    = node.struct.NumberOfIdEntries
        for rsrc in node.entries:
            node_y["childs"].append(generate_node_config(rsrc))

    elif type(node) == pefile.ResourceDirEntryData:
        node_y["type"]          = 1
        node_y["Name"]          = str(node.name)
        node_y["id"]            = node.id
        node_y["OffsetToData"]  = node.struct.OffsetToData
        if hasattr(node, "directory"):
            node_y["childs"].append(generate_node_config(node.directory))
        else:
            node_y["childs"].append(generate_node_config(node.data))
    elif type(node) == pefile.ResourceDataEntryData:
        node_y["type"] = 2
        node_y["OffsetToData"] = node.struct.OffsetToData
        node_y["Size"]         = node.struct.Size
        node_y["CodePage"]     = node.struct.CodePage
        node_y["Reserved"]     = node.struct.Reserved
        node_y["Reserved"]     = node.struct.Reserved
        node_y["lang"]         = node.lang
        node_y["sublang"]      = node.sublang
    else:
        print "Unknown type"
        return

    return node_y

def generate_config(binary_path):
    pe     = pefile.PE(binary_path)

    binary = dict()

    dos_header = dict()

    dos_header["e_magic"]    = pe.DOS_HEADER.e_magic
    dos_header["e_cblp"]     = pe.DOS_HEADER.e_cblp
    dos_header["e_crlc"]     = pe.DOS_HEADER.e_crlc
    dos_header["e_cparhdr"]  = pe.DOS_HEADER.e_cparhdr
    dos_header["e_minalloc"] = pe.DOS_HEADER.e_minalloc
    dos_header["e_maxalloc"] = pe.DOS_HEADER.e_maxalloc
    dos_header["e_ss"]       = pe.DOS_HEADER.e_ss
    dos_header["e_sp"]       = pe.DOS_HEADER.e_sp
    dos_header["e_csum"]     = pe.DOS_HEADER.e_csum

    header = dict()

    header["Machine"]              = pe.FILE_HEADER.Machine
    header["NumberOfSections"]     = pe.FILE_HEADER.NumberOfSections
    header["TimeDateStamp"]        = pe.FILE_HEADER.TimeDateStamp
    header["PointerToSymbolTable"] = pe.FILE_HEADER.PointerToSymbolTable
    header["NumberOfSymbols"]      = pe.FILE_HEADER.NumberOfSymbols
    header["SizeOfOptionalHeader"] = pe.FILE_HEADER.SizeOfOptionalHeader
    header["Characteristics"]      = pe.FILE_HEADER.Characteristics

    optional_header = dict()

    optional_header["Magic"]                       = pe.OPTIONAL_HEADER.Magic
    optional_header["MajorLinkerVersion"]          = pe.OPTIONAL_HEADER.MajorLinkerVersion
    optional_header["MinorLinkerVersion"]          = pe.OPTIONAL_HEADER.MinorLinkerVersion
    optional_header["SizeOfCode"]                  = pe.OPTIONAL_HEADER.SizeOfCode
    optional_header["SizeOfInitializedData"]       = pe.OPTIONAL_HEADER.SizeOfInitializedData
    optional_header["SizeOfUninitializedData"]     = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    optional_header["AddressOfEntryPoint"]         = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    optional_header["BaseOfCode"]                  = pe.OPTIONAL_HEADER.BaseOfCode
    if pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE:
        optional_header["BaseOfData"]                  = pe.OPTIONAL_HEADER.BaseOfData
    optional_header["ImageBase"]                   = pe.OPTIONAL_HEADER.ImageBase
    optional_header["SectionAlignment"]            = pe.OPTIONAL_HEADER.SectionAlignment
    optional_header["FileAlignment"]               = pe.OPTIONAL_HEADER.FileAlignment
    optional_header["MajorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    optional_header["MinorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    optional_header["MajorImageVersion"]           = pe.OPTIONAL_HEADER.MajorImageVersion
    optional_header["MinorImageVersion"]           = pe.OPTIONAL_HEADER.MinorImageVersion
    optional_header["MajorSubsystemVersion"]       = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    optional_header["MinorSubsystemVersion"]       = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    optional_header["Reserved1"]                   = pe.OPTIONAL_HEADER.Reserved1
    optional_header["SizeOfImage"]                 = pe.OPTIONAL_HEADER.SizeOfImage
    optional_header["SizeOfHeaders"]               = pe.OPTIONAL_HEADER.SizeOfHeaders
    optional_header["CheckSum"]                    = pe.OPTIONAL_HEADER.CheckSum
    optional_header["Subsystem"]                   = pe.OPTIONAL_HEADER.Subsystem
    optional_header["DllCharacteristics"]          = pe.OPTIONAL_HEADER.DllCharacteristics
    optional_header["SizeOfStackReserve"]          = pe.OPTIONAL_HEADER.SizeOfStackReserve
    optional_header["SizeOfStackCommit"]           = pe.OPTIONAL_HEADER.SizeOfStackCommit
    optional_header["SizeOfHeapReserve"]           = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    optional_header["SizeOfHeapCommit"]            = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    optional_header["LoaderFlags"]                 = pe.OPTIONAL_HEADER.LoaderFlags
    optional_header["NumberOfRvaAndSizes"]         = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    sections = []
    for section in pe.sections:
        sec = dict()
        sec["name"] = str(section.Name).replace("\0", "")
        sec["Misc_VirtualSize"]     = section.Misc_VirtualSize
        sec["VirtualAddress"]       = section.VirtualAddress
        sec["SizeOfRawData"]        = section.SizeOfRawData
        sec["PointerToRawData"]     = section.PointerToRawData
        sec["PointerToRelocations"] = section.PointerToRelocations
        sec["PointerToLinenumbers"] = section.PointerToLinenumbers
        sec["NumberOfRelocations"]  = section.NumberOfRelocations
        sec["NumberOfLinenumbers"]  = section.NumberOfLinenumbers
        sec["Characteristics"]      = section.Characteristics
        sections.append(sec)

    imports = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        import_ = dict()
        import_["name"]           = entry.dll
        import_["TimeDateStamp"]  = entry.struct.TimeDateStamp
        import_["ForwarderChain"] = entry.struct.ForwarderChain
        entries = []
        for imp in entry.imports:
            impo = dict()
            if not imp.import_by_ordinal:
                impo["name"] = imp.name
            else:
                impo["name"] = None

            entries.append(impo)
        import_["entries"] = entries
        imports.append(import_)

    tls = dict()
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        tls["StartAddressOfRawData"] = pe.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData
        tls["EndAddressOfRawData"]   = pe.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData
        tls["AddressOfIndex"]        = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex
        tls["AddressOfCallBacks"]    = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        tls["SizeOfZeroFill"]        = pe.DIRECTORY_ENTRY_TLS.struct.SizeOfZeroFill
        tls["Characteristics"]       = pe.DIRECTORY_ENTRY_TLS.struct.Characteristics

    resources = dict()
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        node = pe.DIRECTORY_ENTRY_RESOURCE
        resources = generate_node_config(node)

    binary["dos_header"]      = dos_header
    binary["header"]          = header
    binary["optional_header"] = optional_header
    binary["sections"]        = sections
    binary["imports"]         = imports
    binary["tls"]             = tls
    binary["resources"]       = resources

    binary["filename"] = str(binary_path).split("/")[-1]
    binary["hash"]     = hashlib.md5(binary_path).hexdigest()

    output = open(binary_path + ".yaml", "w")
    yaml.dump(binary, stream=output)
    output.close()

if __name__ == "__main__":
    path_pe32_binaries = "./samples/PE/win32/"
    path_pe64_binaries = "./samples/PE/win64/"

    for binary in os.listdir(path_pe32_binaries):
        if binary.endswith(".exe") or binary.endswith(".dll"):
            print "[PE32] Dealing with:", binary
            generate_config(path_pe32_binaries + binary)

    for binary in os.listdir(path_pe64_binaries):
        if binary.endswith(".exe") or binary.endswith(".dll"):
            print "[PE64] Dealing with:", binary
            generate_config(path_pe64_binaries + binary)
