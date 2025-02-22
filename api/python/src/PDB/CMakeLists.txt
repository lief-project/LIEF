target_sources(pyLIEF PRIVATE
  init.cpp
  pyBuildMetadata.cpp
  pyCompilationUnit.cpp
  pyDebugInfo.cpp
  pyFunction.cpp
  pyPublicSymbol.cpp
  pyType.cpp
)
add_subdirectory(types)
