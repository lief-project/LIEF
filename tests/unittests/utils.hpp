/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef LIEF_TEST_UTILS_H
#define LIEF_TEST_UTILS_H
#include <string>
namespace LIEF::test {
std::string get_sample_dir();
std::string get_sample(const std::string& name);
std::string get_sample(const std::string& format, const std::string& name);

inline std::string get_elf_sample(const std::string& name) {
  return get_sample("ELF", name);
}

inline std::string get_pe_sample(const std::string& name) {
  return get_sample("PE", name);
}

inline std::string get_macho_sample(const std::string& name) {
  return get_sample("MachO", name);
}

inline std::string get_oat_sample(const std::string& name) {
  return get_sample("OAT", name);
}

}
#endif
