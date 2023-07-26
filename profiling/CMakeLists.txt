set(PROFILING_FLAGS
    -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc
    -fno-builtin-free -fno-omit-frame-pointer -g)
target_compile_options(LIB_LIEF PUBLIC ${PROFILING_FLAGS})

add_executable(elf_profiler elf_profiler.cpp)

set_target_properties(elf_profiler
                      PROPERTIES POSITION_INDEPENDENT_CODE ON
                                 CXX_STANDARD              17
                                 CXX_STANDARD_REQUIRED     ON)

target_compile_options(elf_profiler PUBLIC ${PROFILING_FLAGS})
target_link_libraries(elf_profiler PRIVATE LIB_LIEF)

add_executable(macho_profiler macho_profiler.cpp)
target_compile_options(macho_profiler PUBLIC ${PROFILING_FLAGS})
target_link_libraries(macho_profiler PRIVATE LIB_LIEF)

set_target_properties(macho_profiler
                      PROPERTIES POSITION_INDEPENDENT_CODE ON
                                 CXX_STANDARD              17
                                 CXX_STANDARD_REQUIRED     ON)

add_executable(pe_profiler pe_profilier.cpp)
target_compile_options(pe_profiler PUBLIC ${PROFILING_FLAGS})
target_link_libraries(pe_profiler PRIVATE LIB_LIEF)

set_target_properties(pe_profiler
                      PROPERTIES POSITION_INDEPENDENT_CODE ON
                                 CXX_STANDARD              17
                                 CXX_STANDARD_REQUIRED     ON)

