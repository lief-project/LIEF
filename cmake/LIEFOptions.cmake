if(__add_lief_options)
	return()
endif()
set(__add_lief_options ON)

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
option(LIEF_ENABLE_JSON    "Enable JSON-related APIs"                   ON)
option(LIEF_SHARED_LIB     "Enable shared lib"                          ON)

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

