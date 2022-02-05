#ifndef LIEF_LEAF_H_
#define LIEF_LEAF_H_
#include "LIEF/config.h"

// LEAF raises warnings which pollute the LIEF's warning
// This sequence disables the warning for the include
#if defined(_MSC_VER)
#    pragma warning(push,1)
#elif defined(__clang__)
#    pragma clang system_header
#elif (__GNUC__*100+__GNUC_MINOR__>301)
#    pragma GCC system_header
#endif

#ifndef LIEF_EXTERNAL_LEAF
#include <LIEF/third-party/internal/leaf.hpp>
#else
#include <boost/leaf.hpp>
#endif


#if defined(_MSC_VER)
#pragma warning(pop)
#endif


#endif
