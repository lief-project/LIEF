/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "LIEF/MachO/Builder.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <list>
#include <utility>

#include "LIEF/BinaryStream/BinaryStream.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/UUIDCommand.hpp"
#include "LIEF/exception.hpp"
#include "MachO/Binary.tcc"
#include "MachO/Builder.tcc"
#include "Object.tcc"
#include "logging.hpp"

namespace LIEF {
namespace MachO {

Builder::~Builder() = default;

Builder::Builder(Binary& binary) : binary_{&binary} {
  raw_.reserve(binary_->original_size());
  binaries_.push_back(binary_);
  build();
}

Builder::Builder(std::vector<Binary*> binaries)
    : binaries_{std::move(binaries)} {
  build_fat();
}

Builder::Builder(FatBinary& fat) {
  binaries_.reserve(fat.binaries_.size());
  std::transform(std::begin(fat.binaries_), std::end(fat.binaries_),
                 std::back_inserter(binaries_),
                 [](const std::unique_ptr<Binary>& bin) { return bin.get(); });
  build_fat();
}

void Builder::build() {
  if (binary_->is64_) {
    build<details::MachO64>();
  } else {
    build<details::MachO32>();
  }
}

template <typename T>
ok_error_t Builder::build() {
  if (binaries_.size() > 1) {
    LIEF_ERR("More than one binary!");
    return make_error_code(lief_errors::build_error);
  }

  build_uuid();

  for (std::unique_ptr<LoadCommand>& cmd : binary_->commands_) {
    if (DylibCommand::classof(cmd.get())) {
      build<T>(cmd->as<DylibCommand>());
      continue;
    }

    if (DylinkerCommand::classof(cmd.get())) {
      build<T>(cmd->as<DylinkerCommand>());
      continue;
    }

    if (VersionMin::classof(cmd.get())) {
      build<T>(cmd->as<VersionMin>());
      continue;
    }

    if (SourceVersion::classof(cmd.get())) {
      build<T>(cmd->as<SourceVersion>());
      continue;
    }

    if (MainCommand::classof(cmd.get())) {
      build<T>(cmd->as<MainCommand>());
      continue;
    }

    if (DyldInfo::classof(cmd.get())) {
      build<T>(cmd->as<DyldInfo>());
      continue;
    }

    if (FunctionStarts::classof(cmd.get())) {
      build<T>(cmd->as<FunctionStarts>());
      continue;
    }

    if (SymbolCommand::classof(cmd.get())) {
      build<T>(cmd->as<SymbolCommand>());
      continue;
    }

    if (DynamicSymbolCommand::classof(cmd.get())) {
      build<T>(cmd->as<DynamicSymbolCommand>());
      continue;
    }

    if (DataInCode::classof(cmd.get())) {
      build<T>(cmd->as<DataInCode>());
      continue;
    }

    if (CodeSignature::classof(cmd.get())) {
      build<T>(cmd->as<CodeSignature>());
      continue;
    }

    if (SegmentSplitInfo::classof(cmd.get())) {
      build<T>(cmd->as<SegmentSplitInfo>());
      continue;
    }

    if (SubFramework::classof(cmd.get())) {
      build<T>(cmd->as<SubFramework>());
      continue;
    }

    if (DyldEnvironment::classof(cmd.get())) {
      build<T>(cmd->as<DyldEnvironment>());
      continue;
    }

    if (ThreadCommand::classof(cmd.get())) {
      build<T>(cmd->as<ThreadCommand>());
      continue;
    }

    if (BuildVersion::classof(cmd.get())) {
      build<T>(cmd->as<BuildVersion>());
      continue;
    }
  }

  build_segments<T>();
  build_load_commands();
  // build_symbols<T>();

  build_header();
  return ok();
}

ok_error_t Builder::build_fat() {
  // If there is only one binary don't build a FAT
  if (binaries_.size() == 1) {
    Builder builder{*binaries_.back()};
    raw_.write(builder.get_build());
    return {};
  }
  build_fat_header();
  constexpr auto fat_header_sz = sizeof(details::fat_header);
  constexpr auto fat_arch_sz = sizeof(details::fat_arch);
  for (size_t i = 0; i < binaries_.size(); ++i) {
    auto* arch = reinterpret_cast<details::fat_arch*>(
        raw_.raw().data() + fat_header_sz + i * fat_arch_sz);
    Builder builder{*binaries_[i]};
    std::vector<uint8_t> raw = builder.get_build();
    auto alignment = BinaryStream::swap_endian<uint32_t>(arch->align);
    uint32_t offset = align(raw_.size(), 1 << alignment);

    arch->offset = BinaryStream::swap_endian<uint32_t>(offset);
    arch->size = BinaryStream::swap_endian<uint32_t>(raw.size());
    raw_.seekp(offset);
    raw_.write(std::move(raw));
  }
  return ok();
}

ok_error_t Builder::build_fat_header() {
  LIEF_DEBUG("[+] Building Fat Header");
  static constexpr uint32_t ALIGNMENT = 14;  // 4096 / 0x1000
  details::fat_header header;

  std::memset(&header, 0, sizeof(details::fat_header));

  header.magic = static_cast<uint32_t>(MACHO_TYPES::FAT_CIGAM);
  header.nfat_arch = BinaryStream::swap_endian<uint32_t>(binaries_.size());

  raw_.seekp(0);
  raw_.write(reinterpret_cast<const uint8_t*>(&header),
             sizeof(details::fat_header));

  for (Binary* binary : binaries_) {
    const Header& header = binary->header();
    details::fat_arch arch_header;
    std::memset(&arch_header, 0, sizeof(details::fat_arch));

    arch_header.cputype = BinaryStream::swap_endian<uint32_t>(
        static_cast<uint32_t>(header.cpu_type()));
    arch_header.cpusubtype = BinaryStream::swap_endian<uint32_t>(
        static_cast<uint32_t>(header.cpu_subtype()));
    arch_header.offset = 0;
    arch_header.size = 0;
    arch_header.align = BinaryStream::swap_endian<uint32_t>(ALIGNMENT);
    raw_.write(reinterpret_cast<const uint8_t*>(&arch_header),
               sizeof(details::fat_arch));
  }
  return ok();
}

ok_error_t Builder::build_header() {
  LIEF_DEBUG("[+] Building header");
  const Header& binary_header = binary_->header();
  if (binary_->is64_) {
    details::mach_header_64 header;
    std::memset(&header, 0, sizeof(details::mach_header_64));
    header.magic = static_cast<uint32_t>(binary_header.magic());
    header.cputype = static_cast<uint32_t>(binary_header.cpu_type());
    header.cpusubtype = static_cast<uint32_t>(binary_header.cpu_subtype());
    header.filetype = static_cast<uint32_t>(binary_header.file_type());
    header.ncmds = static_cast<uint32_t>(binary_header.nb_cmds());
    header.sizeofcmds = static_cast<uint32_t>(binary_header.sizeof_cmds());
    header.flags = static_cast<uint32_t>(binary_header.flags());
    header.reserved = static_cast<uint32_t>(binary_header.reserved());

    raw_.seekp(0);
    raw_.write(reinterpret_cast<const uint8_t*>(&header),
               sizeof(details::mach_header_64));
  } else {
    details::mach_header header;
    std::memset(&header, 0, sizeof(details::mach_header));

    header.magic = static_cast<uint32_t>(binary_header.magic());
    header.cputype = static_cast<uint32_t>(binary_header.cpu_type());
    header.cpusubtype = static_cast<uint32_t>(binary_header.cpu_subtype());
    header.filetype = static_cast<uint32_t>(binary_header.file_type());
    header.ncmds = static_cast<uint32_t>(binary_header.nb_cmds());
    header.sizeofcmds = static_cast<uint32_t>(binary_header.sizeof_cmds());
    header.flags = static_cast<uint32_t>(binary_header.flags());

    raw_.seekp(0);
    raw_.write(reinterpret_cast<const uint8_t*>(&header),
               sizeof(details::mach_header));
  }
  return ok();
}

ok_error_t Builder::build_load_commands() {
  LIEF_DEBUG("[+] Building load segments");

  const auto& binary = binaries_.back();
  // Check if the number of segments is correct
  if (binary->header().nb_cmds() != binary->commands_.size()) {
    LIEF_WARN("Error: header.nb_cmds = {:d} vs number of commands #{:d}",
              binary->header().nb_cmds(), binary->commands_.size());
    return make_error_code(lief_errors::build_error);
  }

  for (const SegmentCommand* segment : binary->segments_) {
    span<const uint8_t> segment_content = segment->content();
    raw_.seekp(segment->file_offset());
    raw_.write(segment_content.data(), segment_content.size());
  }

  // uint64_t loadCommandsOffset = raw_.size();
  for (const std::unique_ptr<LoadCommand>& command : binary->commands_) {
    const auto& data = command->data();
    uint64_t loadCommandsOffset = command->command_offset();
    LIEF_DEBUG("[+] Command offset: 0x{:04x}", loadCommandsOffset);
    raw_.seekp(loadCommandsOffset);
    raw_.write(data);
  }
  return ok();
}

ok_error_t Builder::build_uuid() {
  auto* uuid_cmd = binary_->command<UUIDCommand>();
  if (uuid_cmd == nullptr) {
    LIEF_DEBUG("[-] No uuid");
    return ok();
  }

  details::uuid_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::uuid_command));

  raw_cmd.cmd = static_cast<uint32_t>(uuid_cmd->command());
  raw_cmd.cmdsize =
      static_cast<uint32_t>(uuid_cmd->size());  // sizeof(uuid_command)

  const uuid_t& uuid = uuid_cmd->uuid();
  std::copy(std::begin(uuid), std::end(uuid), raw_cmd.uuid);

  if (uuid_cmd->size() < sizeof(details::uuid_command)) {
    LIEF_WARN("Size of original data is different for '{}' -> Skip!",
              to_string(uuid_cmd->command()));
    return make_error_code(lief_errors::build_error);
  }

  std::copy(reinterpret_cast<const uint8_t*>(&raw_cmd),
            reinterpret_cast<const uint8_t*>(&raw_cmd) +
                sizeof(details::uuid_command),
            uuid_cmd->original_data_.data());
  return ok();
}

const std::vector<uint8_t>& Builder::get_build() { return raw_.raw(); }

void Builder::write(MachO::Binary& binary, const std::string& filename) {
  Builder builder{binary};
  builder.write(filename);
}

void Builder::write(FatBinary& fatbinary, const std::string& filename) {
  Builder builder{fatbinary};
  builder.write(filename);
}

void Builder::write(const std::string& filename) const {
  std::ofstream output_file{filename,
                            std::ios::out | std::ios::binary | std::ios::trunc};
  if (output_file) {
    std::vector<uint8_t> content;
    raw_.get(content);

    std::copy(std::begin(content), std::end(content),
              std::ostreambuf_iterator<char>(output_file));
  } else {
    LIEF_ERR("Fail to write binary file");
  }
}

}  // namespace MachO
}  // namespace LIEF
