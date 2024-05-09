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

if (MSVC)
  add_definitions(-DNOMINMAX)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  target_compile_options(LIB_LIEF PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wno-expansion-to-defined
    # Promote this warning into an error as error management
    # where the result is 'result<void>' might miss the "return {}"
    -Werror=return-type
    -fdiagnostics-color=always
  )
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    if(CMAKE_GENERATOR MATCHES "Ninja")
      target_compile_options(LIB_LIEF PRIVATE
        -fcolor-diagnostics
      )
    endif()
  else(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    # GCC specific flags
  endif()

  if (LIEF_DISABLE_EXCEPTIONS)
      target_compile_options(LIB_LIEF PRIVATE -fno-exceptions)
  endif()

endif()

if(MSVC AND NOT CLANG_CL)
  set(msvc_warning_flags
    # Disabled warnings.
    -wd4141 # Suppress ''modifier' : used more than once' (because of __forceinline combined with inline)
    -wd4146 # Suppress 'unary minus operator applied to unsigned type, result still unsigned'
    -wd4244 # Suppress ''argument' : conversion from 'type1' to 'type2', possible loss of data'
    -wd4267 # Suppress ''var' : conversion from 'size_t' to 'type', possible loss of data'
    -wd4291 # Suppress ''declaration' : no matching operator delete found; memory will not be freed if initialization throws an exception'
    -wd4351 # Suppress 'new behavior: elements of array 'array' will be default initialized'
    -wd4456 # Suppress 'declaration of 'var' hides local variable'
    -wd4457 # Suppress 'declaration of 'var' hides function parameter'
    -wd4458 # Suppress 'declaration of 'var' hides class member'
    -wd4459 # Suppress 'declaration of 'var' hides global declaration'
    -wd4503 # Suppress ''identifier' : decorated name length exceeded, name was truncated'
    -wd4624 # Suppress ''derived class' : destructor could not be generated because a base class destructor is inaccessible'
    -wd4722 # Suppress 'function' : destructor never returns, potential memory leak
    -wd4100 # Suppress 'unreferenced formal parameter'
    -wd4127 # Suppress 'conditional expression is constant'
    -wd4512 # Suppress 'assignment operator could not be generated'
    -wd4505 # Suppress 'unreferenced local function has been removed'
    -wd4610 # Suppress '<class> can never be instantiated'
    -wd4510 # Suppress 'default constructor could not be generated'
    -wd4702 # Suppress 'unreachable code'
    -wd4245 # Suppress ''conversion' : conversion from 'type1' to 'type2', signed/unsigned mismatch'
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
        # C4709 is disabled because of a bug with Visual Studio 2017 as of
        # v15.8.8. Re-evaluate the usefulness of this diagnostic when the bug
        # is fixed.
    -wd4709 # Suppress comma operator within array index expression

    # We'd like this warning to be enabled, but it triggers from code in
    # WinBase.h that we don't have control over.
    -wd5105 # Suppress macro expansion producing 'defined' has undefined behavior

    # Ideally, we'd like this warning to be enabled, but even MSVC 2019 doesn't
    # support the 'aligned' attribute in the way that clang sources requires (for
    # any code that uses the LLVM_ALIGNAS macro), so this is must be disabled to
    # avoid unwanted alignment warnings.
    -wd4324 # Suppress 'structure was padded due to __declspec(align())'

    # Promoted warnings.
    -w14062 # Promote 'enumerator in switch of enum is not handled' to level 1 warning.

    # Promoted warnings to errors.
    -we4238 # Promote 'nonstandard extension used : class rvalue used as lvalue' to error.

    -wd4530 # Supress C++ exception handler used, but unwind semantics are not enabled
    -wd4251 # remove: needs to have dll-interface to be used by clients of class
  )

  set(msvc_warning_flags "/W4 ${msvc_warning_flags}")
  string(REGEX REPLACE " /W[0-4]" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  string(REGEX REPLACE " /W[0-4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  foreach(flag ${msvc_warning_flags})
    append("${flag}" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
  endforeach(flag)

  if (LIEF_DISABLE_EXCEPTIONS)
      string(REGEX REPLACE " /EHsc" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
      string(REGEX REPLACE " /EHsc" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
      string(REGEX REPLACE " /EHc" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
      string(REGEX REPLACE " /EHc" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
      target_compile_options(LIB_LIEF PRIVATE /EHsc-)
  endif()
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

