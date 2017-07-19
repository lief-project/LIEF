
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/cpp")

if (LIEF_C_API)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/c")
endif()


install(
  DIRECTORY python
  DESTINATION share/LIEF/examples
  COMPONENT examples
)

install(
  DIRECTORY cmake
  DESTINATION share/LIEF/examples
  COMPONENT examples
)



