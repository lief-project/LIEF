add_subdirectory(cpp)

if (LIEF_C_API)
  add_subdirectory(c)
endif()

if (LIEF_INSTALL)
  install(
    DIRECTORY cmake
    DESTINATION ${CMAKE_INSTALL_DATADIR}/LIEF/examples
    COMPONENT examples
  )
endif()
