target_sources(lief-jni PUBLIC
  Binary.cpp
  Utils.cpp
  LoadConfiguration.cpp
  CodeIntegrity.cpp
  DataDirectory.cpp
  ExceptionInfo.cpp
  RuntimeFunctionX64.cpp
  RuntimeFunctionAArch64.cpp
)
add_subdirectory(aarch64)
add_subdirectory(LoadConfigurations)
