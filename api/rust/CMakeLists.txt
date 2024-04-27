target_include_directories(LIB_LIEF PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")

add_subdirectory(src)

if(LIEF_INSTALL)
  install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT headers)

  install(
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/autocxx_ffi.rs
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/LIEF/)
endif()



