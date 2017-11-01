cmake_minimum_required(VERSION 3.1)


# Python tests
# ============
if (PYTHON_TESTS_ENABLED)
  ADD_PYTHON_TEST(PYTHON_API_TEST
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_python.py")
endif()
