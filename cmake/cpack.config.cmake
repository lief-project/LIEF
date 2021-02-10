include("static-release/CPackConfig.cmake")

set(CPACK_INSTALL_CMAKE_PROJECTS ${CPACK_INSTALL_CMAKE_PROJECTS}
  shared-release LIEF ALL /
  static-release LIEF ALL /
)
