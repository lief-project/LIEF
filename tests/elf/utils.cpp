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
#include <dirent.h>
#include <iostream>

#include <yaml-cpp/yaml.h>

#include "utils.hpp"

extern const YAML::Node config;

namespace LIEF {
namespace ELF {
namespace Test {
std::vector<std::string> get_test_cases(void) {
  std::vector<std::string> elf_samples;
  for (auto it = std::begin(config) ;it != std::end(config); ++it) {
    std::string key = it->first.as<std::string>();
    if (config[key]["format"].as<std::string>() == "ELF") {
      elf_samples.push_back(key);
    }
  }
  return elf_samples;
}

std::vector<std::string> get_binary_test_cases(void) {
  std::vector<std::string> elf_samples;
  for (auto it = std::begin(config) ;it != std::end(config); ++it) {
    std::string key = it->first.as<std::string>();
    if (config[key]["format"].as<std::string>() == "ELF" && config[key]["type"].as<std::string>() == "binary") {
      elf_samples.push_back(key);
    }
  }
  return elf_samples;

}

std::vector<std::string> get_library_test_cases(void) {
  std::vector<std::string> elf_samples;
  for (auto it = std::begin(config) ;it != std::end(config); ++it) {
    std::string key = it->first.as<std::string>();
    if (config[key]["format"].as<std::string>() == "ELF" && config[key]["type"].as<std::string>() == "library") {
      elf_samples.push_back(key);
    }
  }
  return elf_samples;

}

std::vector<std::string> get_elf_files(void) {
  auto endswith = [] (const std::string& string, const std::string& end) {
    size_t pos = string.rfind(end);
    return pos != std::string::npos and pos == (string.length() - end.length());
  };
  std::vector<std::string> filespath;
  DIR *dir;
  struct dirent *ent;
  std::string samples_path = PATH_TO_SAMPLES;
  samples_path += "/ELF";
  if ((dir = opendir(samples_path.c_str())) != NULL) {
    while ((ent = readdir (dir)) != NULL) {
      const std::string name = ent->d_name;
      if (endswith(name, ".bin") or endswith(name, ".so")) {
        filespath.emplace_back(samples_path + "/" + name);
      }
    }
    closedir (dir);
  } else {
    std::cerr << "Can't open '" << samples_path << "'." << std::endl;
  }
  return filespath;
}

}
}
}
