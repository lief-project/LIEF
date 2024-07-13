#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/Abstract/DebugInfo.hpp"

#include "logging.hpp"
#include "messages.hpp"

namespace LIEF {
namespace details {
class DebugInfo {};
}

// ----------------------------------------------------------------------------
// Abstract/Binary.hpp
// ----------------------------------------------------------------------------
DebugInfo* Binary::debug_info() const {
  LIEF_ERR(DEBUG_FMT_NOT_SUPPORTED);
  return nullptr;
}

// ----------------------------------------------------------------------------
// DebugInfo/DebugInfo.hpp
// ----------------------------------------------------------------------------
DebugInfo::DebugInfo(std::unique_ptr<details::DebugInfo>) :
    impl_(nullptr)
{}

DebugInfo::~DebugInfo() = default;

}
