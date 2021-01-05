#include "LIEF/PE/signature/attributes/SpcSpOpusInfo.hpp"
namespace LIEF {
namespace PE {

SpcSpOpusInfo::SpcSpOpusInfo() :
  Attribute(SIG_ATTRIBUTE_TYPES::SPC_SP_OPUS_INFO)
{}

SpcSpOpusInfo::SpcSpOpusInfo(const SpcSpOpusInfo&) = default;
SpcSpOpusInfo& SpcSpOpusInfo::operator=(const SpcSpOpusInfo&) = default;

std::unique_ptr<Attribute> SpcSpOpusInfo::clone(void) const {
  return std::unique_ptr<Attribute>(new SpcSpOpusInfo{*this});
}

SpcSpOpusInfo::SpcSpOpusInfo(std::string program_name, std::string more_info) :
  Attribute(SIG_ATTRIBUTE_TYPES::SPC_SP_OPUS_INFO),
  program_name_{std::move(program_name)},
  more_info_{std::move(more_info)}
{}

void SpcSpOpusInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string SpcSpOpusInfo::print() const {
  std::string out;
  if (not this->program_name().empty()) {
    out = this->program_name();
  }
  if (not this->more_info().empty()) {
    if (not out.empty()) {
      out += " - ";
    }
    out += this->more_info();
  }
  return out;
}


SpcSpOpusInfo::~SpcSpOpusInfo() = default;

}
}
