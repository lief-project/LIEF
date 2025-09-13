target_sources(analysis-core PRIVATE
  Analyzer.cpp
  TypeBuilder.cpp
  AnalyzerBase.cpp
)

add_subdirectory(analyzers)
