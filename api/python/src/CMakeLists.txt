target_include_directories(pyLIEF PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_sources(pyLIEF PRIVATE
  pyLIEF.cpp
  pySafeString.cpp
  pyErr.cpp
  pyIOStream.cpp
  pyutils.cpp
)

add_subdirectory(Abstract)
add_subdirectory(platforms)

add_subdirectory(DWARF)
add_subdirectory(PDB)
add_subdirectory(ObjC)

if(LIEF_ELF)
  add_subdirectory(ELF)
endif()

if(LIEF_PE)
  add_subdirectory(PE)
endif()

if(LIEF_MACHO)
  add_subdirectory(MachO)
endif()

if(LIEF_OAT)
  add_subdirectory(OAT)
endif()

if(LIEF_DEX)
  add_subdirectory(DEX)
endif()

if(LIEF_VDEX)
  add_subdirectory(VDEX)
endif()

if(LIEF_ART)
  add_subdirectory(ART)
endif()

