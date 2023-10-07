if(__add_lief_api)
  return()
endif()
set(__add_lief_api ON)

# Python
# ------
if (LIEF_PYTHON_API)
  add_subdirectory(api/python)
endif()

# C API
# -----
if(LIEF_C_API)
  target_include_directories(LIB_LIEF PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/api/c/include>")

  add_subdirectory(api/c)
endif()

