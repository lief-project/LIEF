target_sources(pyLIEF PRIVATE
  pyRuntimeFunctionX64.cpp
  pyRuntimeFunctionAArch64.cpp
  pyUnwindCodeX64.cpp
)

add_subdirectory(AArch64)
