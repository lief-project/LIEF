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
#include <binaryninja/binaryninjaapi.h>

#include <LIEF/utils.hpp>
#include <LIEF/version.h>

#include "binaryninja/analysis/commands.hpp"
#include "log.hpp"
#include "binaryninja/analysis/Analyzer.hpp"

namespace bn = BinaryNinja;

namespace analysis_plugin::commands {
void register_commands() {
  bn::PluginCommand::Register(
    "LIEF\\Enhance Analysis",
    "Enhance the analysis of the current binary with LIEF",
    run_analysis
  );

  BN_INFO("LIEF analysis plugin registered");

  BN_INFO("LIEF Extended: {}", LIEF::is_extended());
  if (LIEF::is_extended()) {
    LIEF::lief_version_t version = LIEF::extended_version();
    BN_INFO("Extended version: {}.{}.{}.{}",
            version.major, version.minor, version.patch, version.id);
  } else {
    BN_INFO("Version: {}.{}.{}",
            LIEF_VERSION_MAJOR, LIEF_VERSION_MINOR, LIEF_VERSION_PATCH);
  }
}

void run_analysis(BinaryNinja::BinaryView* bv) {
  auto analyzer = Analyzer::from_bv(*bv);
  if (analyzer == nullptr) {
    return;
  }
  analyzer->run();
}

}
