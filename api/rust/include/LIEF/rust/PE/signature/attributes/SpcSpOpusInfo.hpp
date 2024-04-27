#pragma once
#include "LIEF/PE/signature/attributes/SpcSpOpusInfo.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"

class PE_SpcSpOpusInfo : public PE_Attribute {
  public:
  using lief_t = LIEF::PE::SpcSpOpusInfo;
  PE_SpcSpOpusInfo(const lief_t& base) : PE_Attribute(base) {}

  std::string program_name() const { return impl().program_name(); }
  std::string more_info() const { return impl().more_info(); }

  static bool classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
