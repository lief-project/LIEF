target_sources(LIB_LIEF PRIVATE
  Binary.cpp
  Symbol.cpp
  EnumToString.cpp
  Header.cpp
  Section.cpp
  Section.tcc
  Parser.cpp
  Relocation.cpp
  Function.cpp
  hash.cpp
  json_api.cpp)

if(LIEF_ENABLE_JSON)
  target_sources(LIB_LIEF PRIVATE json.cpp)
endif()
