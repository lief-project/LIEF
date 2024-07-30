if(__add_lief_options)
  return()
endif()
set(__add_lief_options ON)
include(CMakeDependentOption)

option(LIEF_TESTS                      "Enable tests"                               OFF)
option(LIEF_DOC                        "Enable documentation"                       OFF)
option(LIEF_PYTHON_API                 "Enable Python Bindings"                     OFF)
option(LIEF_C_API                      "C API"                                      ON)
option(LIEF_EXAMPLES                   "Build LIEF C++ examples"                    ON)
option(LIEF_FORCE32                    "Force build LIEF 32 bits version"           OFF)
option(LIEF_USE_CCACHE                 "Use ccache to speed up compilation"         ON)
option(LIEF_EXTRA_WARNINGS             "Enable extra warning from the compiler"     OFF)
option(LIEF_LOGGING                    "Enable logging"                             ON)
option(LIEF_LOGGING_DEBUG              "Enable debug logging"                       ON)
option(LIEF_ENABLE_JSON                "Enable JSON-related APIs"                   ON)
option(LIEF_OPT_NLOHMANN_JSON_EXTERNAL "Use nlohmann/json externally"               OFF)
option(LIEF_FORCE_API_EXPORTS          "Force exports of API symbols"               OFF)
option(LIEF_PY_LIEF_EXT                "Use a pre-installed version of LIEF for the bindings" OFF)
option(LIEF_RUST_API                   "Generate the C++ bridge for Rust's cxx" OFF)
option(LIEF_DISABLE_EXCEPTIONS         "Disable C++ exceptions on the core library" ON)

option(LIEF_DISABLE_FROZEN "Disable Frozen even if it is supported"     OFF)

option(LIEF_ELF            "Build LIEF with ELF module"                 ON)
option(LIEF_PE             "Build LIEF with PE  module"                 ON)
option(LIEF_MACHO          "Build LIEF with MachO module"               ON)

option(LIEF_DEX            "Build LIEF with DEX module"                 ON)
option(LIEF_ART            "Build LIEF with ART module"                 ON)

# Extended features
option(LIEF_DEBUG_INFO     "Build LIEF with DWARF/PDB support"          OFF)
option(LIEF_OBJC           "Build LIEF with ObjC metadata support"      OFF)

cmake_dependent_option(LIEF_PYTHON_EDITABLE "Make an editable build " OFF
                       "LIEF_PYTHON_API" OFF)

cmake_dependent_option(LIEF_PYTHON_STATIC "Internal usage" OFF
                       "LIEF_PYTHON_API" OFF)

# OAT support relies on the ELF and DEX format.
# Therefore, these options must be enabled to support this format
cmake_dependent_option(LIEF_OAT "Build LIEF with OAT module" ON
                       "LIEF_ELF;LIEF_DEX" OFF)

# VDEX format depends on the DEX module
cmake_dependent_option(LIEF_VDEX "Build LIEF with VDEX module" ON
                       "LIEF_DEX" OFF)

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

# Use a user-provided version of spdlog
# It can be useful to reduce compile time
option(LIEF_EXTERNAL_SPDLOG OFF)

# This option enables to provide an external
# version of TartanLlama/expected (e.g. present on the system)
option(LIEF_OPT_EXTERNAL_EXPECTED OFF)

# This option enables to provide an external version of utf8cpp
option(LIEF_OPT_UTFCPP_EXTERNAL OFF)

# This option enables to provide an external version of MbedTLS
option(LIEF_OPT_MBEDTLS_EXTERNAL OFF)

# This option enables to provide an external version of nanobind
option(LIEF_OPT_NANOBIND_EXTERNAL OFF)

# This option enables to provide an external
# version of https://github.com/tcbrindle/span (e.g. present on the system)
option(LIEF_OPT_EXTERNAL_SPAN OFF)
set(LIEF_EXTERNAL_SPAN_DIR )

# This option enables to provide an external version of Frozen
set(_LIEF_USE_FROZEN ON)
if(LIEF_DISABLE_FROZEN)
  set(_LIEF_USE_FROZEN OFF)
endif()

cmake_dependent_option(LIEF_OPT_FROZEN_EXTERNAL "Use an external provided version of Frozen" OFF
                       "_LIEF_USE_FROZEN" OFF)

# This option enables the install target in the cmake
option(LIEF_INSTALL "Generate the install target." ON)

set(LIEF_ELF_SUPPORT 0)
set(LIEF_PE_SUPPORT 0)
set(LIEF_MACHO_SUPPORT 0)

set(LIEF_OAT_SUPPORT 0)
set(LIEF_DEX_SUPPORT 0)
set(LIEF_VDEX_SUPPORT 0)
set(LIEF_ART_SUPPORT 0)

set(LIEF_JSON_SUPPORT 0)
set(LIEF_NLOHMANN_JSON_EXTERNAL 0)
set(LIEF_LOGGING_SUPPORT 0)
set(LIEF_LOGGING_DEBUG_SUPPORT 0)
set(LIEF_FROZEN_ENABLED 0)
set(LIEF_EXTERNAL_FROZEN 0)

set(LIEF_EXTERNAL_EXPECTED 0)
set(LIEF_EXTERNAL_UTF8CPP 0)
set(LIEF_EXTERNAL_MBEDTLS 0)
set(LIEF_EXTERNAL_SPAN 0)

set(LIEF_DEBUG_INFO_SUPPORT 0)
set(LIEF_OBJC_SUPPORT 0)
set(LIEF_EXTENDED 0)

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
  if(LIEF_OPT_NLOHMANN_JSON_EXTERNAL)
    set(LIEF_NLOHMANN_JSON_EXTERNAL 1)
  endif()
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
  if(LIEF_OPT_FROZEN_EXTERNAL)
    set(LIEF_EXTERNAL_FROZEN 1)
  endif()
endif()

if(LIEF_OPT_EXTERNAL_EXPECTED)
  set(LIEF_EXTERNAL_EXPECTED 1)
endif()

if(LIEF_OPT_UTFCPP_EXTERNAL)
  set(LIEF_EXTERNAL_UTF8CPP 1)
endif()

if(LIEF_OPT_MBEDTLS_EXTERNAL)
  set(LIEF_EXTERNAL_MBEDTLS 1)
endif()

if(LIEF_OPT_EXTERNAL_SPAN)
  set(LIEF_EXTERNAL_SPAN 1)
endif()

if(LIEF_PYTHON_API)
  if(LIEF_OPT_NANOBIND_EXTERNAL)
    set(LIEF_EXTERNAL_NANOBIND 1)
  endif()
endif()

# Extended features
if (LIEF_DEBUG_INFO)
  set(LIEF_DEBUG_INFO_SUPPORT 1)
endif()

if (LIEF_OBJC)
  set(LIEF_OBJC_SUPPORT 1)
endif()

if (LIEF_DEBUG_INFO OR LIEF_OBJC) # or any other extended feature
  set(LIEF_EXTENDED 1)
endif()
