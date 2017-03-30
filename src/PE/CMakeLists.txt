set(LIEF_PE_SRC
  ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ExportEntry.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Binary.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Symbol.cpp
  ${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DosHeader.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ResourceDirectory.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Import.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ResourceNode.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Export.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Section.cpp
  ${CMAKE_CURRENT_LIST_DIR}/OptionalHeader.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Builder.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Parser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ResourcesManager.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Relocation.cpp
  ${CMAKE_CURRENT_LIST_DIR}/TLS.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Debug.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ImportEntry.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ResourceData.cpp
  ${CMAKE_CURRENT_LIST_DIR}/RelocationEntry.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DataDirectory.cpp

  ${CMAKE_CURRENT_LIST_DIR}/signature/AuthenticatedAttributes.cpp
  ${CMAKE_CURRENT_LIST_DIR}/signature/ContentInfo.cpp
  ${CMAKE_CURRENT_LIST_DIR}/signature/Signature.cpp
  ${CMAKE_CURRENT_LIST_DIR}/signature/SignerInfo.cpp
  ${CMAKE_CURRENT_LIST_DIR}/signature/x509.cpp
  ${CMAKE_CURRENT_LIST_DIR}/signature/OIDToString.cpp
  )

target_sources(LIB_LIEF_STATIC PRIVATE ${LIEF_PE_SRC})
target_sources(LIB_LIEF_SHARED PRIVATE ${LIEF_PE_SRC})


file(READ ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/enums.inc      LIEF_PE_ENUMS)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/structures.inc LIEF_PE_STRUCTURES)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/enums.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/PE/enums.hpp
  @ONLY
)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/Structures.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/PE/Structures.hpp
  @ONLY
)

