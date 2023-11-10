#ifndef PY_LIEF_NB_UTILS_H
#define PY_LIEF_NB_UTILS_H

#include <nanobind/nanobind.h>
#include <LIEF/BinaryStream/SpanStream.hpp>
#include <vector>
#include <memory>

#include "nanobind/extra/memoryview.hpp"

NAMESPACE_BEGIN(NB_NAMESPACE)

inline nanobind::bytes to_bytes(const std::vector<uint8_t>& vec) {
  return nanobind::bytes(reinterpret_cast<const char*>(vec.data()), vec.size());
}

inline nanobind::bytes to_bytes(LIEF::span<const uint8_t> sp) {
  return nanobind::bytes(reinterpret_cast<const char*>(sp.data()), sp.size());
}

inline nanobind::bytes to_bytes(const std::string& str) {
  return nanobind::bytes(str.data(), str.size());
}

inline nanobind::memoryview to_memoryview(LIEF::span<const uint8_t> sp) {
  return nanobind::memoryview::from_memory(sp.data(), sp.size());
}

inline nanobind::memoryview to_memoryview(const std::vector<uint8_t>& vec) {
  return nanobind::memoryview::from_memory(vec.data(), vec.size());
}

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
