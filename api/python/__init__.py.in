#!/usr/bin/env python

import sys
import _pylief
from _pylief import *

__version__ = _pylief.__version__

sys.modules["lief.PE"]    = _pylief.PE
sys.modules["lief.ELF"]   = _pylief.ELF

sys.modules["lief.ELF.ELF32"]   = _pylief.ELF.ELF32
sys.modules["lief.ELF.ELF64"]   = _pylief.ELF.ELF64

sys.modules["lief.MachO"] = _pylief.MachO
