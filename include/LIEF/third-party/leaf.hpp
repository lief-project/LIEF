#ifndef LIEF_LEAF_H_
#define LIEF_LEAF_H_

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

// First step to enable users to provide their own (system) dependency
#define LIEF_EXTERNAL_THIRD_PARTY 0

#if !LIEF_EXTERNAL_THIRD_PARTY
#include <LIEF/third-party/internal/leaf.hpp>
#else
// TODO
#endif


#if defined(__GNUG__) || defined(__clang__)
#  pragma GCC diagnostic pop
#endif

#endif
