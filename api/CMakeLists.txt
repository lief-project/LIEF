if (LIEF_PYTHON_API)
  add_subdirectory(python)
endif()

if(LIEF_C_API)
  add_subdirectory(c)
endif()

if(LIEF_RUST_API)
  add_subdirectory(rust)
endif()

