add_subdirectory(generic)

add_subdirectory(elf)
add_subdirectory(pe)
add_subdirectory(macho)

add_subdirectory(dwarf)

target_sources(lief-jni PUBLIC
  Utils.cpp
)
