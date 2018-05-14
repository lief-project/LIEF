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

set(LIEF_MACHO_SRC
  "${CMAKE_CURRENT_LIST_DIR}/utils.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/UUIDCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Symbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/FatBinary.cpp"
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
  "${CMAKE_CURRENT_LIST_DIR}/DylinkerCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DyldInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Builder.tcc"
  "${CMAKE_CURRENT_LIST_DIR}/Binary.tcc"
  "${CMAKE_CURRENT_LIST_DIR}/BinaryParser.tcc"
  "${CMAKE_CURRENT_LIST_DIR}/FunctionStarts.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SourceVersion.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/VersionMin.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Relocation.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/RelocationObject.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/RelocationDyld.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/BindingInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ExportInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ThreadCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/RPathCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ParserConfig.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/hash.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/CodeSignature.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SegmentSplitInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DataInCode.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DataCodeEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SubFramework.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DyldEnvironment.cpp"
)

set(LIEF_MACHO_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/FatBinary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/Binary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/BinaryParser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/Builder.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/DylibCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/DylinkerCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/EnumToString.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/LoadCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/MainCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/Parser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/Section.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/SegmentCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/Symbol.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/SymbolCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/type_traits.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/DyldInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/UUIDCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/FunctionStarts.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/Structures.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/enums.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/SourceVersion.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/VersionMin.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/Relocation.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/RelocationObject.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/RelocationDyld.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/BindingInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/ExportInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/RPathCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/ThreadCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/ParserConfig.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/hash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/CodeSignature.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/SegmentSplitInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/DataInCode.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/DataCodeEntry.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/SubFramework.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/DyldEnvironment.hpp"
  )

# JSON Part
# =========
set(LIEF_MACHO_JSON_SRC "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
set(LIEF_MACHO_JSON_HDR "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO/json.hpp")


if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_MACHO_SRC           ${LIEF_MACHO_JSON_SRC})
  list(APPEND LIEF_MACHO_INCLUDE_FILES ${LIEF_MACHO_JSON_HDR})
endif()

source_group("Header Files\\MachO" FILES ${LIEF_MACHO_INCLUDE_FILES})
source_group("Source Files\\MachO" FILES ${LIEF_MACHO_SRC})

if (LIEF_MACHO)
  target_sources(LIB_LIEF_STATIC PRIVATE ${LIEF_MACHO_SRC} ${LIEF_MACHO_INCLUDE_FILES})
  target_sources(LIB_LIEF_SHARED PRIVATE ${LIEF_MACHO_SRC} ${LIEF_MACHO_INCLUDE_FILES})
endif()
