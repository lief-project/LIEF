if (PYTHON_TESTS_ENABLED)
  add_test(PYTHON_API_TEST
    ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
    ${PYTHON_EXECUTABLE} -m pytest
      ${CMAKE_CURRENT_SOURCE_DIR}/test_python.py)
endif()
