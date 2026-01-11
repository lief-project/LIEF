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
#include "binaryninja/dwarf-export/commands.hpp"
#include "binaryninja/dwarf-export/log.hpp"
#include "binaryninja/dwarf-export/DwarfExport.hpp"

namespace bn = BinaryNinja;

namespace dwarf_plugin::commands {
void register_commands() {
  bn::PluginCommand::Register(
    "LIEF\\Export as DWARF", "Generate a DWARF file",
    dwarf_export
  );

  BN_INFO("LIEF DWARF plugin registered");

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

void dwarf_export(BinaryNinja::BinaryView* bv) {
  if (!LIEF::is_extended()) {
    bn::ShowMessageBox(
      "Error", "This feature requires LIEF extended.",
      /*buttons=*/OKButtonSet, /*icon=*/ErrorIcon
    );
    return;
  }
  std::string result;
  if (!bn::GetSaveFileNameInput(result, "Save Location")) {
    return;
  }
  auto exporter = DwarfExport::from_bv(*bv);
  exporter->save(result);
  bn::ShowMessageBox(
    "Info", fmt::format("DWARF saved here: {}", result),
    /*buttons=*/OKButtonSet, /*icon=*/InformationIcon
  );

}

}
