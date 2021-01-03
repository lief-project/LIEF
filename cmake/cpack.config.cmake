include("static-release/CPackConfig.cmake")

set(CPACK_INSTALL_CMAKE_PROJECTS ${CPACK_INSTALL_CMAKE_PROJECTS}
  static-release LIEF ALL /
  shared-release LIEF ALL /
)
