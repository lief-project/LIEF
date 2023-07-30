target_sources(LIB_LIEF PRIVATE
  errors.cpp
  hash_stream.cpp
  logging.cpp
  iostream.cpp
  utils.cpp
  internal_utils.cpp
  Object.tcc
  Visitor.cpp
  json_api.cpp
  visitors/hash.cpp
)

add_subdirectory(BinaryStream)
add_subdirectory(Abstract)
add_subdirectory(platforms)

if(LIEF_ENABLE_JSON)
  target_sources(LIB_LIEF PRIVATE visitors/json.cpp)
endif()

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

