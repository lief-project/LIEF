target_sources(analysis-core PRIVATE
  commands.cpp
  Analyzer.cpp
  AnalyzerBase.cpp
  TypeBuilder.cpp
)
add_subdirectory(PE)
add_subdirectory(ELF)
add_subdirectory(MachO)
add_subdirectory(COFF)
add_subdirectory(DSC)
