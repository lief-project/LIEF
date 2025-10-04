target_sources(pyLIEF PRIVATE
  init.cpp
  pyCompilationUnit.cpp
  pyDebugInfo.cpp
  pyEditor.cpp
  pyFunction.cpp
  pyParameter.cpp
  pyScope.cpp
  pyType.cpp
  pyVariable.cpp
  pyLexicalBlock.cpp
)

add_subdirectory(types)
add_subdirectory(editor)
