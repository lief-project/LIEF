
#include "LIEF/logging++.hpp"
#include "LIEF/filesystem/filesystem.h"

#include "LIEF/OAT/Parser.hpp"
#include "LIEF/OAT/utils.hpp"
#include "LIEF/OAT/Structures.hpp"

#include "LIEF/VDEX.hpp"

#include "Parser.tcc"

namespace LIEF {
namespace OAT {

Parser::~Parser(void) = default;
Parser::Parser(void)  = default;


Binary* Parser::parse(const std::string& oat_file) {
  if (not is_oat(oat_file)) {
    LOG(FATAL) << "'" + oat_file + "' is not an OAT";
    return nullptr;
  }

  Parser parser{oat_file};
  parser.init(oat_file);
  return parser.oat_binary_;
}


Binary* Parser::parse(const std::string& oat_file, const std::string& vdex_file) {
  if (not is_oat(oat_file)) {
    return nullptr;
  }

  if (not VDEX::is_vdex(vdex_file)) {
    return nullptr;
  }
  Parser parser{oat_file};
  parser.set_vdex(VDEX::Parser::parse(vdex_file));
  parser.init(oat_file);
  return parser.oat_binary_;

}

Binary* Parser::parse(const std::vector<uint8_t>& data, const std::string& name) {
  Parser parser{data, name};
  parser.init(name);
  return parser.oat_binary_;
}


Parser::Parser(const std::vector<uint8_t>& data, const std::string& name) :
  oat_binary_{new Binary{}},
  stream_{nullptr}
{
  LIEF::ELF::Parser{data, name, LIEF::ELF::DYNSYM_COUNT_METHODS::COUNT_AUTO, this->oat_binary_};
}

Parser::Parser(const std::string& file) :
  LIEF::Parser{file},
  oat_binary_{new Binary{}},
  stream_{nullptr}
{
  LIEF::ELF::Parser{file, LIEF::ELF::DYNSYM_COUNT_METHODS::COUNT_AUTO, this->oat_binary_};
}


bool Parser::has_vdex(void) const {
  return this->vdex_file_ != nullptr;
}

void Parser::set_vdex(VDEX::File* file) {
  this->vdex_file_ = file;
}


void Parser::init(const std::string& name) {
  VLOG(VDEBUG) << "Parsing binary: " << name << std::endl;

  oat_version_t version = OAT::version(*this->oat_binary_);

  if (this->has_vdex()) {
    this->oat_binary_->vdex_ = this->vdex_file_;
  }

  if (not this->has_vdex() and version > OAT_088::oat_version) {
    LOG(WARNING) << "No VDEX provided with this OAT file. Parsing will be incomplete";
  }

  if (version <= OAT_064::oat_version) {
    return this->parse_binary<OAT64_t>();
  }

  if (version <= OAT_079::oat_version) {
    return this->parse_binary<OAT79_t>();
  }

  if (version <= OAT_088::oat_version) {
    return this->parse_binary<OAT88_t>();
  }

  if (version <= OAT_124::oat_version) {
    return this->parse_binary<OAT124_t>();
  }

  if (version <= OAT_131::oat_version) {
    return this->parse_binary<OAT131_t>();
  }

}


void Parser::bind_vdex(void) {
  CHECK_NE(this->vdex_file_, nullptr);
  for (DEX::File& dex_file : this->vdex_file_->dex_files()) {
    this->oat_binary_->dex_files_.push_back(&dex_file);
  }
}


} // namespace OAT
} // namespace LIEF
