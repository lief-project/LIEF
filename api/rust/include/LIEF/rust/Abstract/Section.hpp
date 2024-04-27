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
#include <LIEF/Abstract/Section.hpp>
#include <LIEF/rust/helpers.hpp>
#include <LIEF/rust/Span.hpp>
#include <LIEF/rust/Mirror.hpp>

#include <string>

class AbstractSection : public Mirror<LIEF::Section> {
  public:
  using Mirror::Mirror;

  std::string name() const { return get().name(); }
  uint64_t size() const { return get().size(); }
  uint64_t offset() const { return get().offset(); }
  uint64_t virtual_address() const { return get().virtual_address(); }
  Span content() const { return make_span(get().content()); }
};
