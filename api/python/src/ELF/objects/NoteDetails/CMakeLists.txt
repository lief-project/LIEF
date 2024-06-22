target_sources(pyLIEF PRIVATE
  pyAndroidIdent.cpp
  pyNoteAbi.cpp
  pyNoteGnuProperty.cpp
  pyQNXStack.cpp
)

add_subdirectory(core)
add_subdirectory(properties)

