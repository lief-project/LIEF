target_sources(pyLIEF PRIVATE
  init.cpp
  pyType.cpp
  pyCompilationUnit.cpp
  pyDebugInfo.cpp
  pyFunction.cpp
  pyPublicSymbol.cpp
)
add_subdirectory(types)
