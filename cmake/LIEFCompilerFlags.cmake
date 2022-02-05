include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
if(__add_lief_compiler_flags)
	return()
endif()
set(__add_lief_compiler_flags ON)

function(append value)
  foreach(variable ${ARGN})
    set(${variable} "${${variable}} ${value}" PARENT_SCOPE)
  endforeach(variable)
endfunction()

function(append_if condition value)
  if (${condition})
    foreach(variable ${ARGN})
      set(${variable} "${${variable}} ${value}" PARENT_SCOPE)
    endforeach(variable)
  endif()
endfunction()

macro(ADD_FLAG_IF_SUPPORTED flag name)
  CHECK_C_COMPILER_FLAG("${flag}"   "C_SUPPORTS_${name}")
  CHECK_CXX_COMPILER_FLAG("${flag}" "CXX_SUPPORTS_${name}")

  if (C_SUPPORTS_${name})
    target_compile_options(LIB_LIEF PRIVATE ${flag})
  endif()

  if (CXX_SUPPORTS_${name})
    target_compile_options(LIB_LIEF PRIVATE ${flag})
  endif()
endmacro()



if (MSVC)
  add_definitions(-DNOMINMAX)
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  if (UNIX)
    if (LIEF_FORCE32)
      target_compile_options(LIB_LIEF PRIVATE -m32)

      set_property(TARGET LIB_LIEF PROPERTY LINK_FLAGS -m32)
    endif()
  endif()

endif()

if (NOT MSVC)
  ADD_FLAG_IF_SUPPORTED("-Wall"                     WALL)
  ADD_FLAG_IF_SUPPORTED("-Wextra"                   WEXTRA)
  ADD_FLAG_IF_SUPPORTED("-Wpedantic"                WPEDANTIC)
  ADD_FLAG_IF_SUPPORTED("-fno-stack-protector"      NO_STACK_PROTECTOR)
  ADD_FLAG_IF_SUPPORTED("-fomit-frame-pointer"      OMIT_FRAME_POINTER)
  ADD_FLAG_IF_SUPPORTED("-fno-strict-aliasing"      NO_STRICT_ALIASING)
  ADD_FLAG_IF_SUPPORTED("-fexceptions"              EXCEPTION)
  ADD_FLAG_IF_SUPPORTED("-Wno-expansion-to-defined" NO_EXPANSION_TO_DEFINED)

  # Promote this warning into an error as Leaf error management
  # where the result is 'result<void>' might miss the "return {}"
  ADD_FLAG_IF_SUPPORTED("-Werror=return-type" ERR_RET_TYPE)


  ADD_FLAG_IF_SUPPORTED("-fdiagnostics-color=always" DIAGNOSTICS_COLOR)
  ADD_FLAG_IF_SUPPORTED("-fcolor-diagnostics"        COLOR_DIAGNOSTICS)
endif()

#ADD_FLAG_IF_SUPPORTED("-Wduplicated-cond"         HAS_DUPLICATED_COND)
#ADD_FLAG_IF_SUPPORTED("-Wduplicated-branches"     HAS_DUPLICATED_BRANCHES)
#ADD_FLAG_IF_SUPPORTED("-Wlogical-op"              HAS_LOGICAL_OP)
#ADD_FLAG_IF_SUPPORTED("-Wshadow"                  HAS_SHADOW)
# =========================================
# MSVC FLAGS
# This part is inspired from LLVM:
# https://github.com/llvm-mirror/llvm/blob/a86576d8771c89502d239f0b85a1a6992020aa47/cmake/modules/HandleLLVMOptions.cmake
# =========================================
set(msvc_warning_flags
  # Disabled warnings.
  -wd4141 # Suppress ''modifier' : used more than once' (because of __forceinline combined with inline)
  -wd4146 # Suppress 'unary minus operator applied to unsigned type, result still unsigned'
  -wd4180 # Suppress 'qualifier applied to function type has no meaning; ignored'
  -wd4244 # Suppress ''argument' : conversion from 'type1' to 'type2', possible loss of data'
  -wd4258 # Suppress ''var' : definition from the for loop is ignored; the definition from the enclosing scope is used'
  -wd4267 # Suppress ''var' : conversion from 'size_t' to 'type', possible loss of data'
  -wd4291 # Suppress ''declaration' : no matching operator delete found; memory will not be freed if initialization throws an exception'
  -wd4345 # Suppress 'behavior change: an object of POD type constructed with an initializer of the form () will be default-initialized'
  -wd4351 # Suppress 'new behavior: elements of array 'array' will be default initialized'
  -wd4355 # Suppress ''this' : used in base member initializer list'
  -wd4456 # Suppress 'declaration of 'var' hides local variable'
  -wd4457 # Suppress 'declaration of 'var' hides function parameter'
  -wd4458 # Suppress 'declaration of 'var' hides class member'
  -wd4459 # Suppress 'declaration of 'var' hides global declaration'
  -wd4503 # Suppress ''identifier' : decorated name length exceeded, name was truncated'
  -wd4624 # Suppress ''derived class' : destructor could not be generated because a base class destructor is inaccessible'
  -wd4722 # Suppress 'function' : destructor never returns, potential memory leak
  -wd4800 # Suppress ''type' : forcing value to bool 'true' or 'false' (performance warning)'
  -wd4100 # Suppress 'unreferenced formal parameter'
  -wd4127 # Suppress 'conditional expression is constant'
  -wd4512 # Suppress 'assignment operator could not be generated'
  -wd4505 # Suppress 'unreferenced local function has been removed'
  -wd4610 # Suppress '<class> can never be instantiated'
  -wd4510 # Suppress 'default constructor could not be generated'
  -wd4702 # Suppress 'unreachable code'
  -wd4245 # Suppress 'signed/unsigned mismatch'
  -wd4706 # Suppress 'assignment within conditional expression'
  -wd4310 # Suppress 'cast truncates constant value'
  -wd4701 # Suppress 'potentially uninitialized local variable'
  -wd4703 # Suppress 'potentially uninitialized local pointer variable'
  -wd4389 # Suppress 'signed/unsigned mismatch'
  -wd4611 # Suppress 'interaction between '_setjmp' and C++ object destruction is non-portable'
  -wd4805 # Suppress 'unsafe mix of type <type> and type <type> in operation'
  -wd4204 # Suppress 'nonstandard extension used : non-constant aggregate initializer'
  -wd4577 # Suppress 'noexcept used with no exception handling mode specified; termination on exception is not guaranteed'
  -wd4091 # Suppress 'typedef: ignored on left of '' when no variable is declared'
      # C4592 is disabled because of false positives in Visual Studio 2015
      # Update 1. Re-evaluate the usefulness of this diagnostic with Update 2.
  -wd4592 # Suppress ''var': symbol will be dynamically initialized (implementation limitation)
  -wd4319 # Suppress ''operator' : zero extending 'type' to 'type' of greater size'
  -wd4710 # Suppress 'function not inlined'
  -wd4820 # Suppress 'XXX bytes padding added after data member'
  -wd4514 # Suppress 'unreferenced inline function has been removed'

  # Ideally, we'd like this warning to be enabled, but MSVC 2013 doesn't
  # support the 'aligned' attribute in the way that clang sources requires (for
  # any code that uses the LLVM_ALIGNAS macro), so this is must be disabled to
  # avoid unwanted alignment warnings.
  # When we switch to requiring a version of MSVC that supports the 'alignas'
  # specifier (MSVC 2015?) this warning can be re-enabled.
  -wd4324 # Suppress 'structure was padded due to __declspec(align())'

  # Promoted warnings.
  -w14062 # Promote 'enumerator in switch of enum is not handled' to level 1 warning.

  # Promoted warnings to errors.
  -we4238 # Promote 'nonstandard extension used : class rvalue used as lvalue' to error.
)

if (MSVC)
  set(msvc_warning_flags "/W4 ${msvc_warning_flags}")
  string(REGEX REPLACE " /W[0-4]" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  string(REGEX REPLACE " /W[0-4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  #foreach(flag ${msvc_warning_flags})
  #  target_compile_options(LIB_LIEF PRIVATE ${flag})
  #endforeach(flag)
endif()

# Speed up MSVC build
if (MSVC_IDE)
  set(LIEF_COMPILER_JOBS "0" CACHE STRING
    "Number of parallel compiler jobs. 0 means use all processors. Default is 0.")
  if (NOT LIEF_COMPILER_JOBS STREQUAL "1")
    if(LIEF_COMPILER_JOBS STREQUAL "0")
      message(STATUS "Number of parallel compiler jobs set to /MP")
      add_definitions(/MP)
    else()
      message(STATUS "Number of parallel compiler jobs set to /MP${LIEF_COMPILER_JOBS}")
      add_definitions(/MP${LIEF_COMPILER_JOBS})
    endif()
  else()
    message(STATUS "Parallel compilation disabled")
  endif()
endif()

