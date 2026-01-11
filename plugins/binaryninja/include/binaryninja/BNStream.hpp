/* Copyright 2025 - 2026 R. Thomas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once
#include <memory>
#include <LIEF/BinaryStream/BinaryStream.hpp>

#include <binaryninja/binaryninjaapi.h>

namespace binaryninja {
class BNStream : public LIEF::BinaryStream {
  public:
  static constexpr auto STREAM_TYPE = (1u << 10) + 1;

  BNStream() = delete;

  BNStream(const BNStream& other) = default;
  BNStream& operator=(const BNStream& other) = default;

  BNStream(BNStream&& other) noexcept = default;
  BNStream& operator=(BNStream&& other) noexcept = default;

  BNStream(BinaryNinja::BinaryView& bv) :
    LIEF::BinaryStream((LIEF::BinaryStream::STREAM_TYPE)STREAM_TYPE),
    bv_(&bv)
  {
    setpos(bv.GetStart());
  }

  static std::unique_ptr<BNStream> from_bv(BinaryNinja::BinaryView& bv) {
    return std::make_unique<BNStream>(bv);
  }

  static bool classof(const BinaryStream& stream) {
    return stream.type() == (LIEF::BinaryStream::STREAM_TYPE)STREAM_TYPE;
  }

  uint64_t size() const override {
    return bv_->GetLength();
  }

  LIEF::ok_error_t peek_in(void* dst, uint64_t offset, uint64_t size,
                           uint64_t virtual_address = 0) const override
  {
    if (bv_->IsValidOffset(virtual_address) &&
        bv_->IsValidOffset(virtual_address + size - 1))
    {
      bv_->Read(dst, virtual_address, size);
      return LIEF::ok();
    }

    if (bv_->IsValidOffset(offset) &&
        bv_->IsValidOffset(offset + size - 1))
    {
      bv_->Read(dst, offset, size);
      return LIEF::ok();
    }

    return make_error_code(lief_errors::read_error);
  }

  LIEF::result<const void*> read_at(uint64_t, uint64_t, uint64_t) const override {
    return make_error_code(lief_errors::not_supported);
  }

  std::unique_ptr<BNStream> clone() const {
    return std::unique_ptr<BNStream>(new BNStream(*this));
  }

  ~BNStream() override = default;
  protected:
  BinaryNinja::BinaryView* bv_ = nullptr;
};
}
