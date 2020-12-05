cmake_minimum_required(VERSION 3.1)
include(ExternalProject)

# Python tests
# ============
if (PYTHON_TESTS_ENABLED)

  # Unit tests
  # ----------
  ADD_PYTHON_TEST(UNITTEST_PYTHON_vdex
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/vdex_test.py")

endif()
