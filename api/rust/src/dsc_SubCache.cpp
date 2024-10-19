#include "LIEF/rust/DyldSharedCache/SubCache.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/rust/DyldSharedCache/DyldSharedCache.hpp"

std::unique_ptr<dsc_DyldSharedCache> dsc_SubCache::cache() const {
  return details::try_unique<dsc_DyldSharedCache>(get().cache()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks
}
