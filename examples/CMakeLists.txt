add_subdirectory(cpp)

if (LIEF_C_API)
  add_subdirectory(c)
endif()

if (LIEF_INSTALL)
  install(
    DIRECTORY cmake
    DESTINATION share/LIEF/examples
    COMPONENT examples
  )
endif()
