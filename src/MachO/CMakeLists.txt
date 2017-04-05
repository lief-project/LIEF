set(LIEF_MACHO_SRC
  "${CMAKE_CURRENT_LIST_DIR}/utils.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/UUIDCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Symbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicSymbolCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/BinaryParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Builder.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SegmentCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Parser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SymbolCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MainCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DylibCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DylinkerCommand.cpp")


target_sources(LIB_LIEF_STATIC PRIVATE ${LIEF_MACHO_SRC})
target_sources(LIB_LIEF_SHARED PRIVATE ${LIEF_MACHO_SRC})


file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/enums.inc"      LIEF_MACHO_ENUMS)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/structures.inc" LIEF_MACHO_STRUCTURES)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/enums.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/enums.hpp"
  @ONLY
)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/Structures.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/Structures.hpp"
  @ONLY
)
