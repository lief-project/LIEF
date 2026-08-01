add_subdirectory(cpp)

if (LIEF_INSTALL)
  install(
    DIRECTORY cmake
    DESTINATION ${CMAKE_INSTALL_DATADIR}/LIEF/examples
    COMPONENT examples
  )
endif()
