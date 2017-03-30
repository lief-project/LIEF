#!/usr/bin/env python2
#-*- coding: utf-8 -*-

# This file is used to generate config file for LIEF test
# It uses `Macholib`(https://pypi.python.org/pypi/macholib/) to generate yaml config file

import re
import yaml
import hashlib
from macholib.MachO import MachO
import sys


macho   = MachO(sys.argv[1])
# Not FAT for now
assert(len(macho.headers) == 1)

binary = dict()

header = dict()

m_header = macho.headers[0]
header["magic"]      = m_header.MH_MAGIC
header["cputype"]    = m_header.header.cputype
header["cpusubtype"] = m_header.header.cpusubtype
header["filetype"]   = m_header.header.filetype
header["ncmds"]      = m_header.header.ncmds
header["sizeofcmds"] = m_header.header.sizeofcmds
header["flags"]      = m_header.header.flags
header["reserved"]   = m_header.header.reserved

binary["header"] = header

for lc, cmd, data in m_header.commands:
    print lc.get_cmd_name()
    print cmd.describe()
    print len(data)


print header
