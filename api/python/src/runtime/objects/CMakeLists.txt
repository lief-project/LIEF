target_sources(pyLIEF PRIVATE
  pyProcess.cpp
  pyModule.cpp
  pyHost.cpp
  pyMemory.cpp
  pyMemoryLayout.cpp
  pyDisassembler.cpp
  pyAssembler.cpp
)

add_subdirectory(linux)
add_subdirectory(windows)
add_subdirectory(android)
add_subdirectory(osx)
