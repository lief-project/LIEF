set(LIEF_PE_RESOURCES_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/resources/ResourceVersion.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/resources/ResourceDialog.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/resources/ResourceDialogItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/resources/ResourceVersion.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/resources/ResourceFixedFileInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/resources/ResourceVarFileInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/resources/ResourceStringFileInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/resources/LangCodeItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/resources/ResourceIcon.hpp"
)

set(LIEF_PE_RESOURCES_SRC
  "${CMAKE_CURRENT_LIST_DIR}/LangCodeItem.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceAccelerator.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceDialog.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceDialogItem.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceFixedFileInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceIcon.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceStringFileInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceStringTable.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceVarFileInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceVersion.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ResourceVersion.cpp"
)

source_group("Source Files\\PE\\Resources" FILES ${LIEF_PE_RESOURCES_SRC})
source_group("Source Files\\PE\\Resources" FILES ${LIEF_PE_RESOURCES_INCLUDE_FILES})

if (LIEF_PE)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_PE_RESOURCES_SRC}
    ${LIEF_PE_RESOURCES_INCLUDE_FILES}
  )
endif()

