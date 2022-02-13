#ifndef LIEF_SPAN_H
#define LIEF_SPAN_H
#include <LIEF/third-party/span.hpp>

namespace LIEF {

template <typename ElementType, std::size_t Extent = tcb::dynamic_extent>
using span = tcb::span<ElementType, Extent>;
}

#endif
