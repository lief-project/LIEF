#!/usr/bin/env python2
#-*- coding: utf-8 -*-

# This file is used to generate config file for LIEF test
# Basically it parse it parse the output of readelf

import re
import yaml
import subprocess
import sys
import hashlib

p = subprocess.Popen(["readelf", "-a", sys.argv[1]], stdout=subprocess.PIPE)
(output, err) = p.communicate()

data = output
binary = dict()
header = dict()

#
# File info
#
binary["filename"] = str(sys.argv[1]).split("/")[-1]
binary["hash"]     = hashlib.md5(sys.argv[1]).hexdigest()
#path: "@CMAKE_CURRENT_SOURCE_DIR@/samples/ELF/x86-64/binaries/ls"

#
# header
#
entrypoint    = re.search("Adresse du point d'entrée:\s+0x([0-9a-f]+)", data).groups()[0]
sectionoffset = re.search("Début des en-têtes de section\s*:\s+([0-9]+)", data).groups()[0]
offsetToPhdr  = re.search("Début des en-têtes de programme :\s+([0-9]+)", data).groups()[0]
nbShdr        = re.search("Nombre d'en-têtes de section\s*:\s+([0-9]+)", data).groups()[0]
nbPhdr        = re.search("Nombre d'en-tête du programme\s*:\s+([0-9]+)", data).groups()[0]
header['entryPoint']   = int(entrypoint, 16)
header['offsetToShdr'] = int(sectionoffset)
header['offsetToPhdr'] = int(offsetToPhdr)
header['nbShdr']       = int(nbShdr)
header['nbPhdr']       = int(nbPhdr)

#
# Sections
#
section_regexp   = re.compile(ur'\[\s*(\d+)\]\s?(\S+|\s*)\s+\S+\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\n\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)', re.MULTILINE)
sections_yaml = []
sections = re.findall(section_regexp, data)
for section in sections:
    section_yaml = {
            'nb'     : int(section[0]),
            'name'   : '%s' % (section[1].strip()),
            'address': int(section[2],16),
            'offset' : int(section[3],16),
            'size'   : int(section[4],16)
            }

    sections_yaml.append(section_yaml)

#
# Segments
#
segment_regexp  = re.compile(ur'\s+(\w+)\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)\n\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)', re.MULTILINE)
segments        = re.findall(segment_regexp, data)
segments_yaml   = []
for segment in segments:
    segment_yaml = {
            'offset'  : int(segment[1], 16),
            'vAddress': int(segment[2], 16),
            'pAddress': int(segment[3], 16),
            'fSize'   : int(segment[4], 16),
            'vSize'   : int(segment[5], 16)
            }
    segments_yaml.append(segment_yaml)

#
# Relocations
#
#relocations_regexp  = re.compile(ur'^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.\S+)\s+([0-9a-fA-F]+)\s+(.\S+)', re.MULTILINE)
#relocations         = re.findall(relocations_regexp, data)
#relocations_yaml    = []
#for relocation in relocations:
#    relocation_yaml = {
#        'offset': int(relocation[0], 16),
#        'info'  : int(relocation[1], 16),
#        'name'  : relocation[4]
#    }
#    if relocation_yaml not in relocations_yaml:
#        relocations_yaml.append(relocation_yaml);

#
# Dynamic symboles
#
extract_regexp = re.compile(ur'^T(?:.*)\.dynsym.*\n((?:\s{2,}(?:.*)\n)+)', re.MULTILINE)
dynsyms_yaml   = []
if len(re.findall(extract_regexp, data)) > 0:
    extracted      = re.findall(extract_regexp, data)[0]
    dynsyms_regexp = re.compile(ur'([0-9]+):\s+[0-9a-fA-F]+\s+[0-9]+\s+\S+\s+\S+\s+\S+\s+\S+\s?([^@\n]*)', re.MULTILINE)
    dynsyms        = re.findall(dynsyms_regexp, extracted)
    dynsyms_yaml   = []
    for dynsym in dynsyms:
        dynsym_yaml = {
            'num' : int(dynsym[0]),
            'name': dynsym[1]
        }
        dynsyms_yaml.append(dynsym_yaml)

#
# Static symbols
#
extract_regexp = re.compile(ur'^T(?:.*)\.symtab.*\n((?:.*\n)+)$\s', re.MULTILINE)
staticsyms = []
extracted = ""
if len(re.findall(extract_regexp, data)) > 0:
    extracted      = re.findall(extract_regexp, data)[0]
    staticsyms_regexp = re.compile(ur'([0-9]+):\s+[0-9a-fA-F]+\s+[0-9]+\s+\S+\s+\S+\s+\S+\s+\S+ (\S*)[@\n]+', re.MULTILINE)
    staticsyms        = re.findall(staticsyms_regexp, extracted)
staticsyms_yaml   = []

for staticsym in staticsyms:
    staticsym_yaml = {
        'num' : int(staticsym[0]),
        'name': staticsym[1]
    }
    staticsyms_yaml.append(staticsym_yaml)


#
# Dynamic Relocations
#
extract_regexp     = re.compile(ur'^S(?:.*)\.rel[a]*\.dyn.*\n((?:.{2,}(?:.*)\n)+)', re.MULTILINE)
relocations_dyn_yaml = []
if len(re.findall(extract_regexp, data)) > 0:
    extracted          = re.findall(extract_regexp, data)[0]
    regexp             = re.compile(ur'^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\S+\s+([0-9a-fA-F]+)\s*(?:\n|(?:\s+(\S+)))', re.MULTILINE)
    relocations        = re.findall(regexp, extracted)
    relocations_dyn_yaml   = []
    for reloc in relocations:
        relocation_yaml = {
            'offset' : int(reloc[0], 16),
            'info'   : int(reloc[1], 16),
            'value'  : int(reloc[2], 16),
            'name'   : reloc[3]
        }
        relocations_dyn_yaml.append(relocation_yaml)

#
# .plt.got relocations
#
extract_regexp     = re.compile(ur'^S(?:.*)\.rel[a]*\.plt.*\n((?:.{2,}(?:.*)\n)+)', re.MULTILINE)
extracted          = re.findall(extract_regexp, data)[0]
regexp             = re.compile(ur'^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\S+\s+([0-9a-fA-F]+)\s*(?:\n|(?:\s+(\S+)))', re.MULTILINE)
relocations        = re.findall(regexp, extracted)
relocations_plt_yaml   = []
for reloc in relocations:
    relocation_yaml = {
        'offset' : int(reloc[0], 16),
        'info'   : int(reloc[1], 16),
        'value'  : int(reloc[2], 16),
        'name'   : reloc[3]
    }
    relocations_plt_yaml.append(relocation_yaml)

binary['Header']          = header
binary['Sections']        = sections_yaml
binary['Segments']        = segments_yaml
#binary['Relocations']     = relocations_yaml
if len(relocations_plt_yaml) > 0:
    binary['PltGotReloc']     = relocations_plt_yaml

if len(dynsyms_yaml) > 0:
    binary['DynamicSymbols'] = dynsyms_yaml

if len(relocations_dyn_yaml) > 0:
    binary['DynamicReloc'] = relocations_dyn_yaml

if len(staticsyms_yaml) > 0:
    binary['StaticSymbols'] = staticsyms_yaml

output = open(binary["filename"] + ".yaml", "w")
yaml.dump(binary, stream=output)
output.close()
