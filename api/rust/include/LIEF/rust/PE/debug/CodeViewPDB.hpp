/* Copyright 2024 - 2026 R. Thomas
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

#include "LIEF/rust/PE/debug/CodeView.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/PE/debug/CodeViewPDB.hpp"

class PE_CodeViewPDB : public PE_CodeView {
  public:
  using lief_t = LIEF::PE::CodeViewPDB;
  PE_CodeViewPDB(const lief_t& obj) :
    PE_CodeView(obj) {}
  PE_CodeViewPDB(std::unique_ptr<LIEF::PE::CodeViewPDB> obj) :
    PE_CodeView(std::move(obj)) {}

  static auto create() {
    return std::make_unique<PE_CodeViewPDB>(
        std::make_unique<LIEF::PE::CodeViewPDB>()
    );
  }

  static auto create_with_filename(const std::string& filename) {
    return std::make_unique<PE_CodeViewPDB>(
        std::make_unique<LIEF::PE::CodeViewPDB>(filename)
    );
  }

  auto age() const {
    return impl().age();
  }

  auto guid() const {
    return to_unique_string(impl().guid());
  }

  auto filename() const {
    return to_unique_string(impl().filename());
  }

  auto signature() const {
    return make_unique_vector<uint64_t>(details::make_vector(impl().signature()));
  }

  auto set_filename(const std::string& filename) {
    impl().filename(filename);
  }

  auto set_age(uint32_t age) {
    impl().age(age);
  }

  auto set_signature(const uint8_t* array, size_t size) {
    assert(sizeof(LIEF::PE::CodeViewPDB::signature_t) == size);
    LIEF::PE::CodeViewPDB::signature_t sig;
    std::copy(array, array + size, sig.begin());
    impl().signature(sig);
  }

  static auto classof(const PE_Debug& entry) {
    return lief_t::classof(&entry.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
  lief_t& impl() {
    return as<lief_t>(this);
  }
};
