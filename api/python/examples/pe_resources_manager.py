#!/usr/bin/env python
import sys
import lief

b = lief.PE.parse(sys.argv[1])
manager = b.resources_manager
print(manager)
print(manager.manifest)
