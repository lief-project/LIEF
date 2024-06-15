/* Copyright 2024 R. Thomas
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

#include "LIEF/PE/signature/ContentInfo.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_ContentInfo_Content : public Mirror<LIEF::PE::ContentInfo::Content> {
  public:
  using lief_t = LIEF::PE::ContentInfo::Content;
  using Mirror::Mirror;

  LIEF::PE::oid_t content_type() const {
    return get().content_type();
  }
};

class PE_ContentInfo : private Mirror<LIEF::PE::ContentInfo> {
  public:
  using lief_t = LIEF::PE::ContentInfo;
  using Mirror::Mirror;

  LIEF::PE::oid_t content_type() const {
    return get().content_type();
  }

  auto value() const {
    return std::make_unique<PE_ContentInfo_Content>(get().value());
  }

  auto digest_algorithm() const {
    return to_int(get().digest_algorithm());
  }

  auto digest() const {
    return get().digest();
  }
};
