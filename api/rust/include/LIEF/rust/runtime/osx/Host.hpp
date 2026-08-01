/* Copyright 2022 - 2026 R. Thomas
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

#include "LIEF/runtime/osx/Host.hpp"
#include "LIEF/rust/helpers.hpp"

class runtime_osx_Host {
  public:
  using lief_t = LIEF::runtime::osx::Host;

  static auto os_version_name() {
    return to_unique_string(lief_t::os_version_name());
  }

  static auto is_sip_enabled() {
    return lief_t::is_sip_enabled();
  }
};

class runtime_osx_Host_version_t {
  public:
  using lief_t = LIEF::runtime::osx::Host::version_t;

  runtime_osx_Host_version_t() :
    impl_(0, 0, 0) {}

  runtime_osx_Host_version_t(const lief_t& v) :
    impl_(v) {}

  uint32_t get_major() const {
    return impl_.major;
  }
  uint32_t get_minor() const {
    return impl_.minor;
  }
  uint32_t get_patch() const {
    return impl_.patch;
  }

  auto to_string() const {
    return to_unique_string(impl_.to_string());
  }

  static auto os_version() {
    return std::make_unique<runtime_osx_Host_version_t>(
        LIEF::runtime::osx::Host::os_version()
    );
  }

  static auto big_sur() {
    return std::make_unique<runtime_osx_Host_version_t>(lief_t::BigSur());
  }

  static auto monterey() {
    return std::make_unique<runtime_osx_Host_version_t>(lief_t::Monterey());
  }

  static auto ventura() {
    return std::make_unique<runtime_osx_Host_version_t>(lief_t::Ventura());
  }

  static auto sonoma() {
    return std::make_unique<runtime_osx_Host_version_t>(lief_t::Sonoma());
  }

  static auto sequoia() {
    return std::make_unique<runtime_osx_Host_version_t>(lief_t::Sequoia());
  }

  static auto tahoe() {
    return std::make_unique<runtime_osx_Host_version_t>(lief_t::Tahoe());
  }

  private:
  lief_t impl_;
};
