target_sources(pyLIEF PRIVATE
  init.cpp
  pyCompilationUnit.cpp
  pyDebugInfo.cpp
  pyFunction.cpp
  pyScope.cpp
  pyType.cpp
  pyVariable.cpp
)

add_subdirectory(types)
