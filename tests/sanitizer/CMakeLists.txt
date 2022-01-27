add_executable(sanitize_checks sanitize_checks.cpp)
target_link_libraries(sanitize_checks PUBLIC LIB_LIEF)

set_target_properties(
  sanitize_checks
  PROPERTIES CXX_STANDARD           11
             CXX_STANDARD_REQUIRED  ON)

target_include_directories(sanitize_checks PUBLIC
                           $<TARGET_PROPERTY:LIB_LIEF,INCLUDE_DIRECTORIES>)

target_compile_options(sanitize_checks PUBLIC ${SANITIZER_FLAGS})
