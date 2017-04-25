import lief

b = lief.parse("/home/romain/dev/LIEF/LIEF/tests/samples/PE/PE64_x86-64_binary_mfc-application.exe")
manager = b.resources_manager
print(manager)
print(manager.manifest)
