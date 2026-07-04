#pragma once
#include "LIEF/PE/signature/attributes/SpcSpOpusInfo.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_SpcSpOpusInfo : public PE_Attribute {
  public:
  using lief_t = LIEF::PE::SpcSpOpusInfo;
  PE_SpcSpOpusInfo(const lief_t& base) :
    PE_Attribute(base) {}

  auto program_name() const {
    return to_unique_string(impl().program_name());
  }
  auto more_info() const {
    return to_unique_string(impl().more_info());
  }

  static auto classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};
