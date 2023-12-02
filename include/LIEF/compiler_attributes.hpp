#ifndef LIEF_COMPILER_ATTR_H
#define LIEF_COMPILER_ATTR_H

#if !defined(_MSC_VER)
#   if __cplusplus >= 201103L
#     define LIEF_CPP11
#     if __cplusplus >= 201402L
#       define LIEF_CPP14
#       if __cplusplus >= 201703L
#         define LIEF_CPP17
#         if __cplusplus >= 202002L
#           define LIEF_CPP20
#         endif
#       endif
#     endif
#   endif
#elif defined(_MSC_VER)
#   if _MSVC_LANG >= 201103L
#     define LIEF_CPP11
#     if _MSVC_LANG >= 201402L
#       define LIEF_CPP14
#       if _MSVC_LANG > 201402L
#         define LIEF_CPP17
#         if _MSVC_LANG >= 202002L
#           define LIEF_CPP20
#         endif
#       endif
#     endif
#   endif
#endif

#if defined(__MINGW32__)
#   define LIEF_DEPRECATED(reason)
#elif defined(LIEF_CPP14)
#   define LIEF_DEPRECATED(reason) [[deprecated(reason)]]
#else
#   define LIEF_DEPRECATED(reason) __attribute__((deprecated(reason)))
#endif

#endif
