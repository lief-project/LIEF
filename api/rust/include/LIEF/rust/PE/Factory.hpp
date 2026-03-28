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
#include <cstdint>
#include <memory>
#include "LIEF/PE/Factory.hpp"
#include "LIEF/rust/PE/Binary.hpp"
#include "LIEF/rust/PE/Section.hpp"

class PE_Factory {
  public:
  static std::unique_ptr<PE_Factory> create(uint32_t pe_type) {
    if (auto factory = LIEF::PE::Factory::create(LIEF::PE::PE_TYPE(pe_type))) {
      return std::make_unique<PE_Factory>(std::move(factory));
    }
    return nullptr;
  }

  auto add_section(const PE_Section& section) {
    factory_->add_section(section.impl());
    return this;
  }

  void set_arch(uint32_t arch) {
    factory_->set_arch(LIEF::PE::Header::MACHINE_TYPES(arch));
  }

  void set_entrypoint(uint64_t ep) {
    factory_->set_entrypoint(ep);
  }

  auto get() {
    return details::try_unique<PE_Binary>(factory_->get());
  }

  auto is_32bit() const { return factory_->is_32bit(); }
  auto is_64bit() const { return factory_->is_64bit(); }
  auto section_align() const { return factory_->section_align(); }
  auto file_align() const { return factory_->file_align(); }

  PE_Factory(std::unique_ptr<LIEF::PE::Factory> f) : factory_(std::move(f)) {}

  private:
  std::unique_ptr<LIEF::PE::Factory> factory_;
};
