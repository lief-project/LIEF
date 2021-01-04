if(__add_lief_options)
  return()
endif()
set(__add_lief_options ON)
include(CMakeDependentOption)

option(LIEF_TESTS          "Enable tests"                               OFF)
option(LIEF_DOC            "Enable documentation"                       OFF)
option(LIEF_PYTHON_API     "Enable Python API"                          ON)
option(LIEF_INSTALL_PYTHON "Install Python bindings"                    OFF)
option(LIEF_C_API          "C API"                                      ON)
option(LIEF_EXAMPLES       "Build LIEF C++ examples"                    ON)
option(LIEF_FORCE32        "Force build LIEF 32 bits version"           OFF)
option(LIEF_COVERAGE       "Perform code coverage"                      OFF)
option(LIEF_USE_CCACHE     "Use ccache to speed up compilation"         ON)
option(LIEF_EXTRA_WARNINGS "Enable extra warning from the compiler"     OFF)
option(LIEF_LOGGING        "Enable logging"                             ON)
option(LIEF_LOGGING_DEBUG  "Enable debug logging"                       ON)
option(LIEF_ENABLE_JSON    "Enable JSON-related APIs"                   ON)

option(LIEF_DISABLE_FROZEN "Disable Frozen even if it is supported"     OFF)

option(LIEF_ELF            "Build LIEF with ELF module"                 ON)
option(LIEF_PE             "Build LIEF with PE  module"                 ON)
option(LIEF_MACHO          "Build LIEF with MachO module"               ON)

option(LIEF_OAT            "Build LIEF with OAT module"                 ON)
option(LIEF_DEX            "Build LIEF with DEX module"                 ON)
option(LIEF_VDEX           "Build LIEF with VDEX module"                ON)
option(LIEF_ART            "Build LIEF with ART module"                 ON)

# Sanitizer
option(LIEF_ASAN "Enable Address sanitizer"   OFF)
option(LIEF_LSAN "Enable Leak sanitizer"      OFF)
option(LIEF_TSAN "Enable Thread sanitizer"    OFF)
option(LIEF_USAN "Enable undefined sanitizer" OFF)

# Fuzzer
option(LIEF_FUZZING "Fuzz LIEF" OFF)

# Profiling
option(LIEF_PROFILING "Enable performance profiling" OFF)

# Install options
cmake_dependent_option(LIEF_INSTALL_COMPILED_EXAMPLES "Install LIEF Compiled examples" OFF
                       "LIEF_EXAMPLES" OFF)

set(LIEF_ELF_SUPPORT 0)
set(LIEF_PE_SUPPORT 0)
set(LIEF_MACHO_SUPPORT 0)

set(LIEF_OAT_SUPPORT 0)
set(LIEF_DEX_SUPPORT 0)
set(LIEF_VDEX_SUPPORT 0)
set(LIEF_ART_SUPPORT 0)

set(LIEF_JSON_SUPPORT 0)
set(LIEF_LOGGING_SUPPORT 0)
set(LIEF_LOGGING_DEBUG_SUPPORT 0)
set(LIEF_FROZEN_ENABLED 0)

if(LIEF_ELF)
  set(LIEF_ELF_SUPPORT 1)
endif()

if(LIEF_PE)
  set(LIEF_PE_SUPPORT 1)
endif()

if(LIEF_MACHO)
  set(LIEF_MACHO_SUPPORT 1)
endif()

if(LIEF_OAT)
  set(LIEF_OAT_SUPPORT 1)
endif()

if(LIEF_DEX)
  set(LIEF_DEX_SUPPORT 1)
endif()

if(LIEF_VDEX)
  set(LIEF_VDEX_SUPPORT 1)
endif()

if(LIEF_ART)
  set(LIEF_ART_SUPPORT 1)
endif()

if(LIEF_ENABLE_JSON)
  set(LIEF_JSON_SUPPORT 1)
endif()

if(LIEF_LOGGING)
  set(LIEF_LOGGING_SUPPORT 1)
  if(LIEF_LOGGING_DEBUG)
    set(LIEF_LOGGING_DEBUG_SUPPORT 1)
  else()
    set(LIEF_LOGGING_DEBUG_SUPPORT 0)
  endif()
endif()

if(NOT LIEF_DISABLE_FROZEN)
  set(LIEF_FROZEN_ENABLED 1)
endif()
