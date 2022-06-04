#include "LIEF/ELF.hpp"
#include "LIEF/PE.hpp"
#include "LIEF/MachO.hpp"
#include "LIEF/DEX.hpp"
#include "LIEF/OAT.hpp"
#include "LIEF/VDEX.hpp"
#include "LIEF/ART.hpp"
#include "logging.hpp"
#include <sstream>

void check(LIEF::PE::Binary& bin) {
  std::stringstream ss;
  ss << bin;
  LIEF::PE::Builder builder{bin};
  builder.build();
}

void check(std::unique_ptr<LIEF::MachO::FatBinary> bin) {
  std::stringstream ss;
  for (LIEF::MachO::Binary& fit : *bin) {
    ss << fit;
    {
      for (size_t i = 0; i < 5; ++i) {
        LIEF::MachO::SegmentCommand seg("__LIEF_" + std::to_string(i), std::vector<uint8_t>(0x345, 1));
        fit.add(seg);
      }
      auto target = &fit;
      if (auto* uuid = target->get(LIEF::MachO::LOAD_COMMAND_TYPES::LC_UUID)) {
        target->extend(*uuid, uuid->size() + 0x100);
      }
      if (auto* seg = target->get_segment("__LINKEDIT")) {
        target->extend(*seg, 0x30000);
      }
      target->remove_signature();
    }
    {
      std::vector<uint8_t> out;
      LIEF::MachO::Builder::write(fit, out);
    }
  }
}

void check(LIEF::ELF::Binary& bin) {
  std::stringstream ss;
  ss << bin;
  LIEF::ELF::Builder builder{bin};
  builder.config().force_relocate = true;
  builder.build();
}

void check(LIEF::DEX::File& file) {
  std::stringstream ss;
  ss << file;
}

void check(LIEF::VDEX::File& file) {
  std::stringstream ss;
  ss << file;
}

void check(LIEF::ART::File& file) {
  std::stringstream ss;
  ss << file;
}


void check(LIEF::OAT::Binary& bin) {
  std::stringstream ss;
  ss << bin;
  for (auto& _ : bin.dex_files()) { ss << _; }
  for (auto& oat_dex : bin.oat_dex_files()) {
    ss << oat_dex;
    check(*oat_dex.dex_file());
  }
  for (auto& cls : bin.classes()) {
    ss << cls;
    ss << *cls.dex_class();
    for (auto& m : cls.methods()) {
      ss << m;
    }
  }
  for (auto& oat_m : bin.methods()) {
    ss << oat_m;
    ss << *oat_m.dex_method();
  }
  ss << bin.dex2dex_json_info();
}

int main(int argc, char** argv) {
  if (argc < 2) {
    LIEF_ERR("Usage: {} <binary>", argv[0]);
    return EXIT_FAILURE;
  }
  const std::string path = argv[1];

  if (LIEF::ELF::is_elf(path)) {
    std::unique_ptr<LIEF::ELF::Binary> bin = LIEF::ELF::Parser::parse(path);
    check(*bin);
    return EXIT_SUCCESS;
  }

  if (LIEF::PE::is_pe(path)) {
    std::unique_ptr<LIEF::PE::Binary> bin = LIEF::PE::Parser::parse(path);
    check(*bin);
    return EXIT_SUCCESS;
  }

  if (LIEF::MachO::is_macho(path)) {
    std::unique_ptr<LIEF::MachO::FatBinary> bin = LIEF::MachO::Parser::parse(path);
    check(std::move(bin));
    return EXIT_SUCCESS;
  }

  if (LIEF::DEX::is_dex(path)) {
    std::unique_ptr<LIEF::DEX::File> bin = LIEF::DEX::Parser::parse(path);
    check(*bin);
    return EXIT_SUCCESS;
  }

  if (LIEF::VDEX::is_vdex(path)) {
    std::unique_ptr<LIEF::VDEX::File> file = LIEF::VDEX::Parser::parse(path);
    check(*file);
    return EXIT_SUCCESS;
  }

  if (LIEF::OAT::is_oat(path)) {
    std::unique_ptr<LIEF::OAT::Binary> bin;
    if (argc > 2) {
      bin = LIEF::OAT::Parser::parse(path, argv[2]);
    } else {
      bin = LIEF::OAT::Parser::parse(path);
    }
    check(*bin);
    return EXIT_SUCCESS;
  }

  if (LIEF::ART::is_art(path)) {
    std::unique_ptr<LIEF::ART::File> bin = LIEF::ART::Parser::parse(path);
    check(*bin);
    return EXIT_SUCCESS;
  }

  return EXIT_SUCCESS;
}
