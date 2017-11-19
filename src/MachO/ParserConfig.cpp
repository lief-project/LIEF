/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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


#include "LIEF/logging++.hpp"

#include "LIEF/MachO/ParserConfig.hpp"


namespace LIEF {
namespace MachO {
ParserConfig::~ParserConfig(void) = default;

ParserConfig& ParserConfig::operator=(const ParserConfig&) = default;
ParserConfig::ParserConfig(const ParserConfig&) = default;


ParserConfig::ParserConfig(void) :
  dyldinfo_deeply_{false}
{}


ParserConfig ParserConfig::deep(void) {
  ParserConfig conf;
  conf.parse_dyldinfo_deeply(true);
  return conf;
}

ParserConfig ParserConfig::quick(void) {
  ParserConfig conf;
  conf.parse_dyldinfo_deeply(false);
  return conf;
}

ParserConfig& ParserConfig::parse_dyldinfo_deeply(bool flag) {
  this->dyldinfo_deeply_ = flag;
  return *this;
}

bool ParserConfig::parse_dyldinfo_deeply(void) const {
  return this->dyldinfo_deeply_;
}



} //namespace MachO
}
