set(PROFILING_FLAGS
    -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc
    -fno-builtin-free -fno-omit-frame-pointer -g -O3)

set(SRC_TARGETS
  elf_profiler.cpp
  macho_profiler.cpp
  pe_profiler.cpp
)

foreach(src_target ${SRC_TARGETS})
  string(REGEX REPLACE ".cpp\$" "" output_name "${src_target}")
  add_executable(${output_name} ${src_target})

  set_target_properties(${output_name}
                        PROPERTIES POSITION_INDEPENDENT_CODE ON
                                   CXX_STANDARD              17
                                   CXX_STANDARD_REQUIRED     ON)

  target_compile_options(${output_name} PUBLIC ${PROFILING_FLAGS})
  target_link_libraries(${output_name} PRIVATE LIB_LIEF)
endforeach()
