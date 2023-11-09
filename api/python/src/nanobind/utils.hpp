#ifndef PY_LIEF_NB_UTILS_H
#define PY_LIEF_NB_UTILS_H

#include <nanobind/nanobind.h>
#include <LIEF/BinaryStream/SpanStream.hpp>
#include <vector>
#include <memory.h>

NAMESPACE_BEGIN(NB_NAMESPACE)

inline std::vector<uint8_t> to_vector(nanobind::bytes bytes) {
  const auto* ptr = reinterpret_cast<const uint8_t*>(bytes.c_str());
  return {ptr, ptr + bytes.size()};
}


inline std::unique_ptr<LIEF::SpanStream> to_stream(nanobind::bytes bytes) {
  const auto* ptr = reinterpret_cast<const uint8_t*>(bytes.c_str());
  return std::make_unique<LIEF::SpanStream>(ptr, bytes.size());
}

NAMESPACE_END(NB_NAMESPACE)

#endif
