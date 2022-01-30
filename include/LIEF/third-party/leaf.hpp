#ifndef LIEF_LEAF_H_
#define LIEF_LEAF_H_
#include "LIEF/config.h"

// LEAF raises warnings which pollute the LIEF's warning
// This sequence disables the warning for the include
#if defined(__GNUG__) || defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wextra-semi"
#  pragma GCC diagnostic ignored "-Wunused-variable"
#  pragma GCC diagnostic ignored "-Wdangling-else"
#  pragma GCC diagnostic ignored "-Wpedantic"
#  pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

#ifndef LIEF_EXTERNAL_LEAF
#include <LIEF/third-party/internal/leaf.hpp>
#else
#include <boost/leaf.hpp>
#endif


#if defined(__GNUG__) || defined(__clang__)
#  pragma GCC diagnostic pop
#endif

#endif
