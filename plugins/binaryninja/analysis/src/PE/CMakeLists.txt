target_sources(analysis-core PRIVATE
  Analyzer.cpp
  AnalyzerBase.cpp
  TypeBuilder.cpp
)

add_subdirectory(analyzers)
