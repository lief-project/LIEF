target_sources(pyLIEF PRIVATE
  init.cpp
  pyEngine.cpp
  pyInstruction.cpp
)

add_subdirectory(aarch64)
add_subdirectory(x86)
add_subdirectory(mips)
add_subdirectory(arm)
add_subdirectory(powerpc)
add_subdirectory(riscv)
add_subdirectory(ebpf)
