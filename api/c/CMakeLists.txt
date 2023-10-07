if(LIEF_ELF)
  add_subdirectory(ELF)
endif()

if(LIEF_PE)
  add_subdirectory(PE)
endif()

if(LIEF_MACHO)
  add_subdirectory(MachO)
endif()

target_sources(LIB_LIEF PRIVATE logging.cpp)
target_include_directories(LIB_LIEF PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
